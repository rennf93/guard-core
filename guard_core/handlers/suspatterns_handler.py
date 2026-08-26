import asyncio
import concurrent.futures
import functools
import io
import ipaddress
import logging
import pickle
import re
import sys
import time
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from typing import Any, NamedTuple

from guard_core.detection_engine import (
    ContentPreprocessor,
    PatternCompiler,
    PerformanceMonitor,
    SemanticAnalyzer,
    looks_like_binary_content,
)
from guard_core.detection_engine.compiler import (
    report_scan_success,
    report_scan_timeout,
    shared_regex_executor,
)
from guard_core.detection_engine.scan_window import bounded_finditer

logger = logging.getLogger("guard_core.handlers.suspatterns")

_DEFAULT_MAX_SCAN_LENGTH = 10000
_DEFAULT_COMPILER_TIMEOUT = 2.0
_DEFAULT_MAX_BODY_INSPECT_BYTES = 262144

_ENHANCED_CONFIG_REQUIRED_ATTRS = (
    "detection_compiler_timeout",
    "detection_max_tracked_patterns",
    "detection_max_content_length",
    "detection_preserve_attack_patterns",
    "detection_anomaly_threshold",
    "detection_slow_pattern_threshold",
    "detection_monitor_history_size",
    "detection_anomaly_emission_cooldown",
    "detection_min_samples_for_anomaly",
    "detection_semantic_threshold",
    "detection_threat_score_threshold",
)


def _supports_enhanced_config(config: Any) -> bool:
    return config is not None and all(
        hasattr(config, attr) for attr in _ENHANCED_CONFIG_REQUIRED_ATTRS
    )


_CTX_XSS = frozenset({"query_param", "header", "request_body", "url_path", "unknown"})
_CTX_SQLI = frozenset({"query_param", "request_body", "unknown"})
_CTX_DIR_TRAVERSAL = frozenset({"url_path", "query_param", "request_body", "unknown"})
_CTX_CMD_INJECTION = frozenset({"query_param", "header", "request_body", "unknown"})
_CTX_FILE_INCLUSION = frozenset({"url_path", "query_param", "request_body", "unknown"})
_CTX_LDAP = frozenset({"query_param", "request_body", "unknown"})
_CTX_XML = frozenset({"header", "request_body", "unknown", "query_param"})
_CTX_SSRF = frozenset({"query_param", "header", "request_body", "url_path", "unknown"})
_CTX_NOSQL = frozenset({"query_param", "request_body", "unknown"})
_CTX_FILE_UPLOAD = frozenset({"header", "request_body", "unknown"})
_CTX_PATH_TRAVERSAL = frozenset({"url_path", "query_param", "request_body", "unknown"})
_CTX_TEMPLATE = frozenset({"query_param", "request_body", "url_path", "unknown"})
_CTX_HTTP_SPLIT = frozenset({"header", "query_param", "request_body", "unknown"})
_CTX_SENSITIVE_FILE = frozenset({"url_path", "request_body", "unknown"})
_CTX_CMS_PROBING = frozenset({"url_path", "request_body", "unknown"})
_CTX_RECON = frozenset({"url_path", "unknown"})
_CTX_PROTO_POLLUTION = frozenset({"query_param", "request_body", "unknown"})
_CTX_CODE_INJECTION = frozenset({"query_param", "request_body", "unknown"})
_CTX_DESERIALIZATION = frozenset({"query_param", "header", "request_body", "unknown"})
_CTX_ALL = frozenset({"query_param", "header", "url_path", "request_body", "unknown"})


ALL_DETECTION_CATEGORIES: frozenset[str] = frozenset(
    {
        "xss",
        "sqli",
        "dir_traversal",
        "path_traversal",
        "cmd_injection",
        "file_inclusion",
        "ldap",
        "xml",
        "ssrf",
        "nosql",
        "file_upload",
        "template",
        "http_split",
        "sensitive_file",
        "cms_probing",
        "recon",
        "proto_pollution",
        "code_injection",
        "deserialization",
    }
)

CATEGORY_CONTEXT_MAP: dict[str, frozenset[str]] = {
    "xss": _CTX_XSS,
    "sqli": _CTX_SQLI,
    "dir_traversal": _CTX_DIR_TRAVERSAL,
    "path_traversal": _CTX_PATH_TRAVERSAL,
    "cmd_injection": _CTX_CMD_INJECTION,
    "file_inclusion": _CTX_FILE_INCLUSION,
    "ldap": _CTX_LDAP,
    "xml": _CTX_XML,
    "ssrf": _CTX_SSRF,
    "nosql": _CTX_NOSQL,
    "file_upload": _CTX_FILE_UPLOAD,
    "template": _CTX_TEMPLATE,
    "http_split": _CTX_HTTP_SPLIT,
    "sensitive_file": _CTX_SENSITIVE_FILE,
    "cms_probing": _CTX_CMS_PROBING,
    "recon": _CTX_RECON,
    "proto_pollution": _CTX_PROTO_POLLUTION,
    "code_injection": _CTX_CODE_INJECTION,
    "deserialization": _CTX_DESERIALIZATION,
}

_SELECT_FROM_RE = r"(?i)\bSELECT\b(?:(?!\bSELECT\b)[\w\s,\*().])*?\bFROM\b"
_SELECT_STAR_RE = r"(?i)SELECT\s+\*"
_WHERE_CLAUSE_RE = r'(?i)\bWHERE\s+[\w."]+\s*(?:=|<|>|<=|>=|LIKE|IN)\b'
_SQLI_TAUTOLOGY_RE = (
    r"(?i)\b(?:OR|AND)\s*(\d+|'[^']*'|\"[^\"]*\"|[@:$][A-Za-z_]\w*)\s*=\s*\1\b"
)

_PATH_ONLY_CHAR_RE = r"[\w.\-~%]"
_PATH_ONLY_SEP_RE = r"[/\\]"
_PATH_ONLY_PREFIX_RE = (
    rf"\A{_PATH_ONLY_SEP_RE}?(?:{_PATH_ONLY_CHAR_RE}+{_PATH_ONLY_SEP_RE})*"
)
_PATH_ONLY_SUFFIX_RE = rf"(?:{_PATH_ONLY_SEP_RE}{_PATH_ONLY_CHAR_RE}*)*(?:\?\S*)?\s*\Z"


def _path_only_pattern(required: str, trailing: str = "") -> str:
    return (
        rf"\A{_PATH_ONLY_SEP_RE}?"
        rf"(?:(?!{required}(?:{_PATH_ONLY_SEP_RE}|\Z))"
        rf"{_PATH_ONLY_CHAR_RE}+{_PATH_ONLY_SEP_RE})*"
        rf"{required}{trailing}{_PATH_ONLY_SUFFIX_RE}"
    )


def _nested_path_pattern(required: str) -> str:
    return (
        rf"\A{_PATH_ONLY_SEP_RE}"
        rf"(?:(?!{required}(?:{_PATH_ONLY_SEP_RE}|\Z))"
        rf"{_PATH_ONLY_CHAR_RE}+{_PATH_ONLY_SEP_RE})*"
        rf"{required}{_PATH_ONLY_SUFFIX_RE}"
    )


_TOP_LEVEL_PATH_PREFIX_RE = rf"\A{_PATH_ONLY_SEP_RE}?"
_TERMINAL_PATH_SUFFIX_RE = rf"(?:{_PATH_ONLY_SEP_RE})?(?:\?\S*)?\s*\Z"

_LDAP_ATTR_DESC_RE = (
    r"(?::)?(?:[a-zA-Z][\w.-]*|\d+(?:\.\d+)*)"
    r"(?:;[\w.-]+)*(?::[\w.-]+)*\s*"
)
_LDAP_ATTR_EXTENSIBLE_MATCH_RE = _LDAP_ATTR_DESC_RE + r":?="

_LDAP_WILDCARD_CHAIN_RE = rf"\*\)[|&]?\(+\s*{_LDAP_ATTR_EXTENSIBLE_MATCH_RE}"
_LDAP_BREAKOUT_BACKWARD_BOUNDARY_CHARS = frozenset("\"'\n&")
_LDAP_BREAKOUT_FORWARD_BOUNDARY_CHARS = frozenset("\"'\n")
_LDAP_BREAKOUT_LOCAL_SCAN_CHARS = 40
_LDAP_BREAKOUT_WILDCARD_CLAUSE_END_RE = re.compile(r"=[^()]+\*\s*\Z")
_LDAP_BREAKOUT_ATTACK_TOKEN_RE = re.compile(r"\*|\(\s*[&|!]|\x00|\(\s*\(|~=|>=|<=")
_LDAP_FILTER_EXPRESSION_STRUCTURE_RE = re.compile(r"[()\"'\n]")

_PROTO_POLLUTION_PROTOTYPE_ASSIGN_RE = r"Object\.prototype\.[A-Za-z_$][\w$]*\s*=(?!=)"
_PROTO_POLLUTION_SET_PROTOTYPE_OF_RE = r"\b(?:Object|Reflect)\.setPrototypeOf\s*\("

_XML_XXE_PUBLIC_EXTERNAL_DTD_RE = (
    r"<!DOCTYPE[^>\[]+PUBLIC[^>\[]+[\"']https?://"
    r"(?!(?:www\.)?w3\.org/)[^\"'>]+[\"'][^>\[]*>"
)

_XSS_JS_SCHEME_CTRL_CHAR_RE = (
    r"j[\t\r\n]*a[\t\r\n]*v[\t\r\n]*a[\t\r\n]*s[\t\r\n]*c[\t\r\n]*r[\t\r\n]*i"
    r"[\t\r\n]*p[\t\r\n]*t[\t\r\n]*:\s*[^\s]+"
)

_FILE_INCLUSION_JSON_VALUE_RE = (
    r"[\"'](?:template|include|tpl|module|layout)[\"']\s*:\s*"
    r"[\"'](?:https?|ftp)://[^\s'\"<>]+/[^\s'\"<>/]*\.(?:phtml|php[3-5]?|"
    r"phar|jsp|aspx?|cgi|pl|py|sh|txt|inc)(?![a-zA-Z0-9])[\"']"
)

_SSRF_BARE_METADATA_ALIAS_RE = r"://(?:metadata|instance-data)(?::\d+)?(?:/|\s|$)"

_CMD_INJECTION_NODE_CHILD_PROCESS_RE = (
    r"(?:require\(\s*[\"']child_process[\"']\s*\)|child_process)\s*\.\s*"
    r"(?:execSync|spawnSync|spawn|fork)\s*\("
)
_CMD_INJECTION_PHP_ASSERT_VARIABLE_RE = r"\bassert\s*\(\s*\$"
_CMD_INJECTION_PYTHON_EXEC_FAMILY_RE = r"\bos\.exec(?:l|le|lp|lpe|v|ve|vp|vpe)\s*\("

_JS_DYNAMIC_EVAL_FUNCTION_CTOR_RE = r"\b(?:new\s+)?Function\s*\(\s*[\"']"
_JS_DYNAMIC_EVAL_BRACKET_RE = r"\[\s*[\"']eval[\"']\s*\]\s*\(\s*[\"']"
_JS_DYNAMIC_EVAL_CTOR_GADGET_RE = (
    r"(?:\.\s*constructor|\[\s*[\"']constructor[\"']\s*\])"
    r"\s*(?:\.\s*constructor|\[\s*[\"']constructor[\"']\s*\])"
    r"\s*\(\s*[\"']"
)
_JS_DYNAMIC_EVAL_TIMER_STRING_ARG_RE = r"\b(?:setTimeout|setInterval)\s*\(\s*[\"']"


_LDAP_PAREN_CONJUNCTION_RE = r"\(\s*[&|]\s*"
_LDAP_PAREN_CONJUNCTION_FOLLOWUP_SYMBOL_RE = re.compile(r"\A\s*(?:[!(]|\*)")
_LDAP_PAREN_CONJUNCTION_FOLLOWUP_ATTR_RE = re.compile(
    rf"\A\s*{_LDAP_ATTR_EXTENSIBLE_MATCH_RE}"
)

_LDAP_WILDCARD_EQUALS_RE = (
    rf"\*\s*\)+\s*(?:[|&!]\s*)?\(+\s*(?:[&|!]|{_LDAP_ATTR_EXTENSIBLE_MATCH_RE})"
)
_LDAP_PAREN_BREAKOUT_RE = rf"\)\s*\(\s*(?:[&|!]|{_LDAP_ATTR_DESC_RE}:?[=~<>])"

_SINGLE_LINE_PREFIX_RE = r"\A(?:(?!\n).)*"
_SINGLE_LINE_SUFFIX_RE = r"(?:[&#;,\"'<>]|\s*\Z)"

_FILE_INCLUSION_HOST_LABEL_RE = r"[0-9a-zA-Z](?:[-\w]*[0-9a-zA-Z])?"
_FILE_INCLUSION_BARE_HOST_RE = (
    rf"(?:(?<!:)\/\/{_FILE_INCLUSION_HOST_LABEL_RE}"
    rf"(?:\.{_FILE_INCLUSION_HOST_LABEL_RE})+(:[0-9]+)?(?:\/?)(?:"
    r"[a-zA-Z0-9\-\.\?,'/\\\+&amp;%\$#_]*)?)"
)

_LDAP_NULL_BYTE_ATTR_RE = (
    r"[a-zA-Z][\w-]*\s*=[\d\w\s]*\*\)+(?:%00|\\u0000|\\x00|\\0|\x00)"
)
_LDAP_NULL_BYTE_BARE_RE = r"\*\)\)+(?:%00|\\u0000|\\x00|\\0|\x00)"
_LDAP_NULL_BYTE_DECODED_ATTR_RE = r"[a-zA-Z][\w-]*\s*=[\d\w\s]*\*\)+\x00"
_LDAP_NULL_BYTE_DECODED_BARE_RE = r"\*\)\)+\x00"

_LDAP_NULL_BYTE_ATTR_COMPILED_RE = re.compile(_LDAP_NULL_BYTE_ATTR_RE, re.IGNORECASE)
_LDAP_NULL_BYTE_DECODED_ATTR_COMPILED_RE = re.compile(
    _LDAP_NULL_BYTE_DECODED_ATTR_RE, re.IGNORECASE
)
_LDAP_NULL_BYTE_TAIL_RE = re.compile(r"\*\)+(?:%00|\\u0000|\\x00|\\0|\x00)")
_LDAP_NULL_BYTE_DECODED_TAIL_RE = re.compile(r"\*\)+\x00")
_LDAP_NULL_BYTE_VALUE_CHAR_RE = re.compile(r"[\d\w\s]")
_LDAP_NULL_BYTE_ATTR_CONTINUATION_CHAR_RE = re.compile(r"[\w-]")
_LDAP_NULL_BYTE_ATTR_LEAD_CHAR_RE = re.compile(r"[a-zA-Z]")
_HTTP_SPLIT_CRLF_RE = r"[\r\n][^\S\r\n]*(?:HTTP\/[0-9.]+|Location:|Set-Cookie:)"
_SQLI_ORDER_BY_TERMINATOR_RE = (
    r"(?i)\bORDER\s+BY\s+\d+\s*(?:--|#|;|\)|,|/\*|\Z)"
    r"|(?<=[=?&])ORDER\s+BY\s+\d+\s*\n"
)
_SQLI_COMMENT_TERMINATOR_RE = r"'\s*[\);]*\s*--|'[\);]*#(?:\n|\Z)"
_PATH_TRAVERSAL_ENCODED_DOT_RE = (
    r"(?:%2e%2e|%252e%252e|%uff0e%uff0e|%c0%ae%c0%ae|%e0%40%ae|%c0%ae"
    r"%e0%80%ae|%25c0%25ae)/"
)
_PATH_TRAVERSAL_SEMICOLON_SEP_RE = r"\.\.;[^/\\]*[/\\]"
_PATH_TRAVERSAL_DECODED_SHAPE_RE = re.compile(r"\.\.[\\/]")
_CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE = (
    r"\n[^\S\r\n]*(?:[^=\s;|&]+=[^\s;|&]+\s+)*(?:/?(?:[\w.-]+/)*env\s+)?/?(?:[\w.-]+/)*"
    r"(?:bash|sh|ksh|csh|tsch|zsh|ash)\s+-c\b"
)
_CMD_INJECTION_SHELL_DASH_FLAG_RE = (
    r"(?:\A|[;|&])\s*(?:/?(?:[\w.-]+/)*env\s+)?/?(?:[\w.-]+/)*"
    r"(?:bash|sh|ksh|csh|tsch|zsh|ash)\s+-[a-zA-Z]+"
)
_DIR_TRAVERSAL_ETC_SENSITIVE_RE = (
    _SINGLE_LINE_PREFIX_RE
    + r"etc/(?:passwd|shadow|group|hosts|motd|issue|mysql/my\.cnf|ssh/ssh_config)"
    + _SINGLE_LINE_SUFFIX_RE
)
_DIR_TRAVERSAL_WINDOWS_INI_RE = (
    _SINGLE_LINE_PREFIX_RE
    + r"(?:boot\.ini|win\.ini|system\.ini|config\.sys)"
    + _SINGLE_LINE_SUFFIX_RE
)
_DIR_TRAVERSAL_PROC_ENVIRON_RE = (
    _SINGLE_LINE_PREFIX_RE + r"proc/self/environ" + _SINGLE_LINE_SUFFIX_RE
)
_DIR_TRAVERSAL_VAR_LOG_RE = (
    _SINGLE_LINE_PREFIX_RE + r"var/log/[^\s/]+" + _SINGLE_LINE_SUFFIX_RE
)
_SSTI_HASH_BRACE_SHAPE_RE = (
    r"#\{\s*[^\}]*(?:@[\w.]+@|\b\w+\s*\("
    r"|['\"]?\d+['\"]?\s*[*/%+\-]\s*['\"]?\d+['\"]?)[^\}]*\}"
)


_DESERIALIZATION_JAVA_B64_RE = r"(?<![A-Za-z0-9+/])(?-i:rO0AB)"
_DESERIALIZATION_DOTNET_B64_RE = r"(?<![A-Za-z0-9+/])(?-i:AAEAAAD)"
_DESERIALIZATION_PICKLE_B64_RE = r"(?<![A-Za-z0-9+/])(?-i:gA[SW]V)"
_DESERIALIZATION_RUBY_B64_RE = r"(?<![A-Za-z0-9+/])(?-i:BAh[Jv7bV])"
_DESERIALIZATION_PICKLE_OS_GLOBAL_RE = r"cos\n"
_PICKLE_IDENT_RE = r"[A-Za-z_][A-Za-z0-9_]{0,100}"
_PICKLE_DOTTED_MODULE_RE = rf"{_PICKLE_IDENT_RE}(?:\.{_PICKLE_IDENT_RE}){{0,20}}"
_DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE = (
    rf"(c{_PICKLE_DOTTED_MODULE_RE}\n{_PICKLE_IDENT_RE}\n)[^ \t]{{0,100}}?[Rb]"
)
_PICKLE_OPCODE_WORK_BUDGET_BYTES = 4096

_FILE_UPLOAD_DANGEROUS_EXTENSIONS = frozenset(
    {
        "phar",
        "phtml",
        "pht",
        "exe",
        "jsp",
        "jspx",
        "aspx",
        "asp",
        "asa",
        "asax",
        "ascx",
        "ashx",
        "asmx",
        "cer",
        "phps",
        "shtml",
        "cfm",
        "cfc",
        "war",
        "bash",
        "sh",
        "rb",
        "py",
        "pl",
        "cgi",
        "com",
        "bat",
        "cmd",
        "vbs",
        "vbe",
        "js",
        "ws",
        "wsf",
        "msi",
        "hta",
    }
)
_FILE_UPLOAD_DANGEROUS_EXT_ALTERNATION = r"php\d*|" + "|".join(
    re.escape(ext)
    for ext in sorted(_FILE_UPLOAD_DANGEROUS_EXTENSIONS, key=lambda c: (-len(c), c))
)
_FILE_UPLOAD_DOUBLE_EXT_EXTENSIONS = _FILE_UPLOAD_DANGEROUS_EXTENSIONS - frozenset(
    {"com"}
)
_FILE_UPLOAD_DOUBLE_EXT_ALTERNATION = r"php\d*|" + "|".join(
    re.escape(ext)
    for ext in sorted(_FILE_UPLOAD_DOUBLE_EXT_EXTENSIONS, key=lambda c: (-len(c), c))
)
_FILE_UPLOAD_BENIGN_TERMINAL_EXTENSIONS = frozenset(
    {
        "jpg",
        "jpeg",
        "png",
        "gif",
        "bmp",
        "webp",
        "svg",
        "ico",
        "tif",
        "tiff",
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "odt",
        "mp3",
        "mp4",
        "avi",
        "mov",
        "wav",
        "webm",
        "mkv",
    }
)
_FILE_UPLOAD_BENIGN_TERMINAL_ALTERNATION = "|".join(
    re.escape(ext)
    for ext in sorted(
        _FILE_UPLOAD_BENIGN_TERMINAL_EXTENSIONS, key=lambda c: (-len(c), c)
    )
)
_FILE_UPLOAD_NULL_OR_SEPARATOR_TRUNCATION_RE = r"(?:%00|\\u0000|\\x00|\\0|\x00|;)"
_ATTR_EQUALS_WHITESPACE_RE = r"\s{0,20}"
_FILE_UPLOAD_ATTR_EQUALS_WHITESPACE_RE = r"\s*"
_HTML_TAG_OPEN_RE = r"<[A-Za-z/]"
_FILE_UPLOAD_FILENAME_EQUALS_RE = (
    r"(?i)filename"
    + _FILE_UPLOAD_ATTR_EQUALS_WHITESPACE_RE
    + r"="
    + _FILE_UPLOAD_ATTR_EQUALS_WHITESPACE_RE
)
_FILE_UPLOAD_DOUBLE_EXTENSION_RE = (
    _FILE_UPLOAD_FILENAME_EQUALS_RE
    + r"[\"'][^\"']*\.(?:"
    + _FILE_UPLOAD_DOUBLE_EXT_ALTERNATION
    + r")(?![A-Za-z0-9])(?:[^ \"'][^\"']*)?\.(?:"
    + _FILE_UPLOAD_BENIGN_TERMINAL_ALTERNATION
    + r")[\"']"
)
_FILE_UPLOAD_TRUNCATION_RE = (
    _FILE_UPLOAD_FILENAME_EQUALS_RE
    + r"[\"'][^\"']*\.(?:"
    + _FILE_UPLOAD_DOUBLE_EXT_ALTERNATION
    + r")(?![A-Za-z0-9])(?:"
    + _FILE_UPLOAD_NULL_OR_SEPARATOR_TRUNCATION_RE
    + r"[^\"']*|\.)[\"']"
)
_FILE_UPLOAD_DECODED_TRUNCATION_RE = (
    _FILE_UPLOAD_FILENAME_EQUALS_RE
    + r"[\"'][^\"']*\.(?:"
    + _FILE_UPLOAD_DOUBLE_EXT_ALTERNATION
    + r")(?![A-Za-z0-9])(?:(?:\x00|;)[^\"']*|\.)[\"']"
)


def _file_upload_scan_window(content: str) -> str:
    return content[: max(content.rfind('"'), content.rfind("'")) + 1]


_CMD_INJECTION_NEWLINE_SHELL_DASH_C_COMPILED_RE = re.compile(
    _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE, re.IGNORECASE
)
_CMD_INJECTION_ASSIGNMENT_PREFIX_RE = re.compile(r"\n[^\S\r\n]*")
_CMD_INJECTION_ASSIGNMENT_TOKEN_RE = re.compile(
    r"[^=\s;|&]+=[^\s;|&]+\s+", re.IGNORECASE
)


def _cmd_injection_shell_dash_c_finditer(
    text: str, compiled: re.Pattern
) -> Iterator[re.Match]:
    last_end = 0
    for prefix_match in _CMD_INJECTION_ASSIGNMENT_PREFIX_RE.finditer(text):
        start = prefix_match.start()
        if start < last_end:
            continue
        pos = prefix_match.end()
        while True:
            token_match = _CMD_INJECTION_ASSIGNMENT_TOKEN_RE.match(text, pos)
            if token_match is None:
                break
            pos = token_match.end()
        match = compiled.match(text, start)
        if match is not None:
            yield match
            last_end = match.end()
        else:
            last_end = pos


def _ldap_null_byte_attr_name_start(text: str, equals_pos: int) -> int | None:
    i = equals_pos
    while i > 0 and _LDAP_NULL_BYTE_ATTR_CONTINUATION_CHAR_RE.match(text, i - 1):
        i -= 1
    if i == equals_pos or not _LDAP_NULL_BYTE_ATTR_LEAD_CHAR_RE.match(text, i):
        return None
    return i


def _ldap_null_byte_value_start(text: str, star_pos: int) -> int:
    i = star_pos
    while i > 0 and _LDAP_NULL_BYTE_VALUE_CHAR_RE.match(text, i - 1):
        i -= 1
    return i


def _ldap_null_byte_attr_finditer(
    text: str, compiled: re.Pattern, tail_re: re.Pattern
) -> Iterator[re.Match]:
    if "*" not in text or ")" not in text:
        return
    last_end = 0
    for tail_match in tail_re.finditer(text):
        star_pos = tail_match.start()
        if star_pos < last_end:
            continue
        value_start = _ldap_null_byte_value_start(text, star_pos)
        if value_start == 0 or text[value_start - 1] != "=":
            continue
        name_start = _ldap_null_byte_attr_name_start(text, value_start - 1)
        if name_start is None:
            continue
        match = compiled.match(text, name_start, tail_match.end())
        if match is not None:
            yield match
            last_end = match.end()


_QUOTE_SPLICE_WORD_CHAR_RE = re.compile(r"\w")
_QUOTE_SPLICE_QUOTE_RUN_RE = re.compile(r"['\"]+")


def _quote_splice_word_start(text: str, pos: int) -> int | None:
    i = pos
    while i > 0 and _QUOTE_SPLICE_WORD_CHAR_RE.match(text, i - 1):
        i -= 1
    return i if i < pos else None


def _quote_splice_finditer(text: str, compiled: re.Pattern) -> Iterator[re.Match]:
    n = len(text)
    last_end = 0
    for quote_match in _QUOTE_SPLICE_QUOTE_RUN_RE.finditer(text):
        if quote_match.start() < last_end:
            continue
        if quote_match.end() >= n or not _QUOTE_SPLICE_WORD_CHAR_RE.match(
            text, quote_match.end()
        ):
            continue
        word_start = _quote_splice_word_start(text, quote_match.start())
        if word_start is None:
            continue
        match = compiled.match(text, word_start)
        if match is not None:
            yield match
            last_end = match.end()
        else:
            last_end = quote_match.end()


_FILE_UPLOAD_DOUBLE_EXT_PREFIX_RE = re.compile(r"filename\s*=\s*[\"']", re.IGNORECASE)
_FILE_UPLOAD_QUOTE_RE = re.compile(r"[\"']")


def _file_upload_double_extension_scan_matches(
    content: str, compiled: re.Pattern
) -> list[re.Match]:
    return list(
        bounded_finditer(
            content, compiled, _FILE_UPLOAD_DOUBLE_EXT_PREFIX_RE, _FILE_UPLOAD_QUOTE_RE
        )
    )


_SQLI_LOAD_FILE_RE = r"(?i)(?:LOAD_FILE\s*\([^)]+\))"
_LOAD_FILE_SCAN_PREFIX_RE = re.compile(r"LOAD_FILE\s*\(", re.IGNORECASE)
_LOAD_FILE_SCAN_TERMINATOR_RE = re.compile(r"\)")


def _load_file_scan_matches(content: str, compiled: re.Pattern) -> list[re.Match]:
    return list(
        bounded_finditer(
            content, compiled, _LOAD_FILE_SCAN_PREFIX_RE, _LOAD_FILE_SCAN_TERMINATOR_RE
        )
    )


_CMD_INJECTION_DOLLAR_SUBSTITUTION_RE = r"(?:[;&|]\s*(?:\$\([^)]+\)|\$\{[^}]+\}))"
_CMD_INJECTION_DOLLAR_PAREN_PREFIX_RE = re.compile(r"[;&|]\s*\$\(")
_CMD_INJECTION_DOLLAR_PAREN_TERMINATOR_RE = re.compile(r"\)")
_CMD_INJECTION_DOLLAR_BRACE_PREFIX_RE = re.compile(r"[;&|]\s*\$\{")
_CMD_INJECTION_DOLLAR_BRACE_TERMINATOR_RE = re.compile(r"\}")


def _cmd_injection_dollar_scan_matches(
    content: str, compiled: re.Pattern
) -> list[re.Match]:
    paren_matches = list(
        bounded_finditer(
            content,
            compiled,
            _CMD_INJECTION_DOLLAR_PAREN_PREFIX_RE,
            _CMD_INJECTION_DOLLAR_PAREN_TERMINATOR_RE,
        )
    )
    brace_matches = list(
        bounded_finditer(
            content,
            compiled,
            _CMD_INJECTION_DOLLAR_BRACE_PREFIX_RE,
            _CMD_INJECTION_DOLLAR_BRACE_TERMINATOR_RE,
        )
    )
    return paren_matches + brace_matches


_TEMPLATE_CURLY_KEYWORD_RE = (
    r"\{\{\s*[^\}]+(?:system|exec|popen|eval|require|include)\s*\}\}"
)
_TEMPLATE_CURLY_PREFIX_RE = re.compile(r"\{\{\s*")
_TEMPLATE_CURLY_TERMINATOR_RE = re.compile(r"\}\}")


def _template_curly_keyword_scan_matches(
    content: str, compiled: re.Pattern
) -> list[re.Match]:
    return list(
        bounded_finditer(
            content, compiled, _TEMPLATE_CURLY_PREFIX_RE, _TEMPLATE_CURLY_TERMINATOR_RE
        )
    )


_TEMPLATE_DOLLAR_BRACE_CALL_RE = (
    r"\$\{[^}]*(?:@[\w.]+@|\b\w+\s*\(|\d+\s*[*/%+\-]\s*\d+)[^}]*\}"
)
_TEMPLATE_DOLLAR_BRACE_PREFIX_RE = re.compile(r"\$\{")
_TEMPLATE_DOLLAR_BRACE_TERMINATOR_RE = re.compile(r"\}")


def _template_dollar_brace_scan_matches(
    content: str, compiled: re.Pattern
) -> list[re.Match]:
    return list(
        bounded_finditer(
            content,
            compiled,
            _TEMPLATE_DOLLAR_BRACE_PREFIX_RE,
            _TEMPLATE_DOLLAR_BRACE_TERMINATOR_RE,
        )
    )


_TEMPLATE_CURLY_CALL_RE = (
    r"\{\{\s*[^\}]*(?:@[\w.]+@|\b\w+\s*\("
    r"|['\"]?\d+['\"]?\s*[*/%+\-]\s*['\"]?\d+['\"]?)[^\}]*\}\}"
)


def _template_curly_call_scan_matches(
    content: str, compiled: re.Pattern
) -> list[re.Match]:
    return list(
        bounded_finditer(
            content, compiled, _TEMPLATE_CURLY_PREFIX_RE, _TEMPLATE_CURLY_TERMINATOR_RE
        )
    )


_TEMPLATE_PERCENT_KEYWORD_RE = (
    r"\{\%\s*[^\%]+(?:system|exec|popen|eval|require|include)\s*\%\}"
)
_TEMPLATE_ASP_KEYWORD_RE = (
    r"(?i)<%[=#]?[^%]*(?:system|exec|eval|`|Runtime|IO\.|File\.|Dir\."
    r"|\d+\s*[-+*/]\s*\d+)[^%]*%>"
)


_PATTERN_SCAN_WINDOW_MATCHERS: dict[
    str, Callable[[str, re.Pattern], list[re.Match]]
] = {
    _SQLI_LOAD_FILE_RE: _load_file_scan_matches,
    _CMD_INJECTION_DOLLAR_SUBSTITUTION_RE: _cmd_injection_dollar_scan_matches,
    _FILE_UPLOAD_DOUBLE_EXTENSION_RE: _file_upload_double_extension_scan_matches,
    _TEMPLATE_CURLY_KEYWORD_RE: _template_curly_keyword_scan_matches,
    _TEMPLATE_DOLLAR_BRACE_CALL_RE: _template_dollar_brace_scan_matches,
    _TEMPLATE_CURLY_CALL_RE: _template_curly_call_scan_matches,
}


DETECTION_RAW_VIEW_PATTERN_SOURCES: frozenset[str] = frozenset(
    {
        _LDAP_NULL_BYTE_ATTR_RE,
        _LDAP_NULL_BYTE_BARE_RE,
        _HTTP_SPLIT_CRLF_RE,
        _SQLI_ORDER_BY_TERMINATOR_RE,
        _SQLI_COMMENT_TERMINATOR_RE,
        _PATH_TRAVERSAL_ENCODED_DOT_RE,
        _SSTI_HASH_BRACE_SHAPE_RE,
        _DESERIALIZATION_JAVA_B64_RE,
        _DESERIALIZATION_DOTNET_B64_RE,
        _DESERIALIZATION_PICKLE_B64_RE,
        _DESERIALIZATION_RUBY_B64_RE,
        _DESERIALIZATION_PICKLE_OS_GLOBAL_RE,
        _DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE,
        _FILE_UPLOAD_TRUNCATION_RE,
        _FILE_UPLOAD_DOUBLE_EXTENSION_RE,
        _XSS_JS_SCHEME_CTRL_CHAR_RE,
    }
)

DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES: frozenset[str] = frozenset(
    {
        _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE,
        _DIR_TRAVERSAL_ETC_SENSITIVE_RE,
        _DIR_TRAVERSAL_WINDOWS_INI_RE,
        _DIR_TRAVERSAL_PROC_ENVIRON_RE,
        _DIR_TRAVERSAL_VAR_LOG_RE,
        _FILE_UPLOAD_DECODED_TRUNCATION_RE,
        _LDAP_NULL_BYTE_DECODED_ATTR_RE,
        _LDAP_NULL_BYTE_DECODED_BARE_RE,
    }
)

_KNOWN_QUADRATIC_BUILTIN_PATTERNS_PENDING_B_XQ_FIX: frozenset[str] = frozenset(
    {
        _XML_XXE_PUBLIC_EXTERNAL_DTD_RE,
        _DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE,
        _TEMPLATE_PERCENT_KEYWORD_RE,
        _TEMPLATE_ASP_KEYWORD_RE,
    }
)

_MEASUREMENT_BORDERLINE_BUILTIN_PATTERNS: frozenset[str] = frozenset(
    {
        _path_only_pattern(
            r"(?:(?!config)[\w-])*config[\w-]*\.(?:env|yml|yaml|json|toml|ini|xml|conf)"
        ),
        _CMD_INJECTION_SHELL_DASH_FLAG_RE,
    }
)

_GLUED_BACKTICK_CANDIDATE_RE = r"(?<!`)`(?:[A-Za-z0-9_./~]|\$[({])(?:[^`\\\n]|\\.)*`"
_GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE = (
    r"\$\((?:[^()\\\n]|\\.)*\)|\$\{(?:[^{}\\\n]|\\.)*\}"
)
_GLUED_BACKTICK_ASCII_WORD_RE = re.compile(r"[A-Za-z0-9_]")

_STRONG_SQL_KEYWORD_GLUED_PREFIX_RE = re.compile(
    r"(?i)\b(?:SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|JOIN|VALUES|ORDER\s+BY|"
    r"GROUP\s+BY)\Z"
)
_STRONG_SQL_KEYWORD_GLUED_SUFFIX_RE = re.compile(
    r"(?i)\A(?:SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|JOIN|VALUES|ORDER\s+BY|"
    r"GROUP\s+BY)\b"
)
_BACKTICK_WINDOW_DELIMITER_CHARS = "`'\"\n\r"
_BACKTICK_WINDOW_DELIMITER_RE = re.compile(r"[`'\"\n\r]")

_IMPLAUSIBLE_SQL_IDENTIFIER_CHARS_RE = re.compile(r"[\s/.;|&$()]")
_IMPLAUSIBLE_DOLLAR_PAREN_TOKEN_CHARS_RE = re.compile(r"[/.;|&$()]")
_BARE_SHELL_PARAMETER_NAME_RE = re.compile(
    r"\A[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z"
)
_SHELL_SPECIAL_PARAMETER_NAMES = frozenset({"ifs"})
_AMBIGUOUS_BACKTICK_INJECTION_CONTEXTS = frozenset({"query_param", "url_path"})
_CTX_CMD_INJECTION_WITH_URL_PATH = frozenset(
    {"query_param", "url_path", "request_body", "unknown"}
)
_CTX_LOG4SHELL = frozenset(
    {"query_param", "header", "request_body", "url_path", "unknown"}
)

_BRACE_EXPANSION_ITEM_RE = r"[^{}\s,:'\"][^{},:'\"]*"
_BRACE_EXPANSION_COMMAND_RE = (
    r"(?:\A|[;&|]\s*|\$\()\{"
    + _BRACE_EXPANSION_ITEM_RE
    + r"(?:,(?:"
    + _BRACE_EXPANSION_ITEM_RE
    + r")?)+\}"
)
_BRACE_EXPANSION_WORD_ITEM_RE = re.compile(r"\A[A-Za-z0-9_./~-]+\Z")
_BRACE_EXPANSION_LETTER_RE = re.compile(r"[A-Za-z]")


def _brace_expansion_is_dangerous_command(match: re.Match) -> bool:
    text = match.group()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return False
    for item in text[start + 1 : end].split(","):
        if _BRACE_EXPANSION_WORD_ITEM_RE.match(
            item
        ) and _BRACE_EXPANSION_LETTER_RE.search(item):
            return True
    return False


_QUOTE_SPLICE_CANDIDATE_RE = r"\w+(?:['\"]+\w+){1,10}"
_QUOTE_SPLICE_CANDIDATE_COMPILED_RE = re.compile(
    _QUOTE_SPLICE_CANDIDATE_RE, re.IGNORECASE
)

_GLOB_WILDCARD_ATOM_RE = r"[A-Za-z0-9_./*?-]*[?*][A-Za-z0-9_./*?-]*"
_GLOB_WILDCARD_PATH_RUN_RE = re.compile(r"[\w./*?-]+")
_GLOB_WILDCARD_CHAR_RE = re.compile(r"[?*]")


def _glob_wildcard_scan_matches(content: str, compiled: re.Pattern) -> list[re.Match]:
    matches = []
    for run_match in _GLOB_WILDCARD_PATH_RUN_RE.finditer(content):
        run_start, run_end = run_match.start(), run_match.end()
        if _GLOB_WILDCARD_CHAR_RE.search(content, run_start, run_end) is None:
            continue
        match = compiled.match(content, run_start, run_end)
        if match is not None:
            matches.append(match)
    return matches


_PATTERN_SCAN_WINDOW_MATCHERS[_GLOB_WILDCARD_ATOM_RE] = _glob_wildcard_scan_matches

_PY_DANGEROUS_MODULE_RE = (
    r"__import__\(\s*['\"](?:os|subprocess|builtins|importlib)['\"]\s*\)"
    r"|\b(?:os|subprocess|builtins|importlib)\b"
)
_PY_DANGEROUS_METHOD_RE = (
    r"system|popen|exec|eval|call|run|Popen|check_output|check_call"
)
_PY_GETATTR_INDIRECTION_RE = (
    r"(?-i:\bgetattr\(\s*(?:" + _PY_DANGEROUS_MODULE_RE + r")\s*,\s*"
    r"['\"](?:" + _PY_DANGEROUS_METHOD_RE + r")['\"]\s*\)\s*\()"
)
_PY_VARS_INDIRECTION_RE = (
    r"(?-i:\bvars\(\s*(?:" + _PY_DANGEROUS_MODULE_RE + r")\s*\)\s*\[\s*"
    r"['\"](?:" + _PY_DANGEROUS_METHOD_RE + r")['\"]\s*\]\s*\()"
)

_SHELL_CHAIN_OPERATOR_RE = re.compile(r";|\|\||\||&&")


def _backtick_token_has_chained_shell_operators(token: str) -> bool:
    return len(_SHELL_CHAIN_OPERATOR_RE.findall(token)) >= 2


_SHELL_METACHARACTER_WINDOW_RE = re.compile(
    r"(?:;|\|\||\||&&)\s*(?:`|[A-Za-z_][\w-]*|[~./][\w./-]*|-[\w-]*)|\$\(|\$\{"
)


def _backtick_pair_glued(content: str, start: int, end: int) -> bool:
    prefix_glued = start > 0 and bool(
        _GLUED_BACKTICK_ASCII_WORD_RE.match(content[start - 1])
    )
    suffix_glued = end < len(content) and bool(
        _GLUED_BACKTICK_ASCII_WORD_RE.match(content[end])
    )
    return prefix_glued or suffix_glued


def _backtick_window_start(content: str, position: int) -> int:
    index = position
    while index > 0 and content[index - 1] not in _BACKTICK_WINDOW_DELIMITER_CHARS:
        index -= 1
    return index


def _backtick_window_end(content: str, position: int) -> int:
    delimiter = _BACKTICK_WINDOW_DELIMITER_RE.search(content, position)
    return delimiter.start() if delimiter else len(content)


def _backtick_pair_context_window(content: str, start: int, end: int) -> str:
    window_start = _backtick_window_start(content, start)
    window_end = _backtick_window_end(content, end)
    return content[window_start:window_end]


_SHELL_TEXT_PRINTABLE_ASCII_RE = re.compile(r"\A[\t\x20-\x7e]*\Z")


def _backtick_token_is_implausible_sql_identifier(token: str) -> bool:
    return bool(_IMPLAUSIBLE_SQL_IDENTIFIER_CHARS_RE.search(token))


def _strong_sql_keyword_glued_to_pair(content: str, start: int, end: int) -> bool:
    window_start = _backtick_window_start(content, start)
    window_end = _backtick_window_end(content, end)
    prefix = content[window_start:start]
    suffix = content[end:window_end]
    if _STRONG_SQL_KEYWORD_GLUED_PREFIX_RE.search(prefix):
        return True
    return bool(_STRONG_SQL_KEYWORD_GLUED_SUFFIX_RE.match(suffix))


def _glued_backtick_pair_is_injection(match: re.Match, context: str) -> bool:
    content = match.string
    start, end = match.start(), match.end()
    token = content[start + 1 : end - 1]
    if not _SHELL_TEXT_PRINTABLE_ASCII_RE.match(token):
        return False
    if _backtick_token_has_chained_shell_operators(token):
        return True
    if not _backtick_pair_glued(content, start, end):
        return False
    if _backtick_token_is_implausible_sql_identifier(token):
        return True
    window = _backtick_pair_context_window(content, start, end)
    if _SHELL_METACHARACTER_WINDOW_RE.search(window):
        return True
    if _strong_sql_keyword_glued_to_pair(content, start, end):
        return False
    return context in _AMBIGUOUS_BACKTICK_INJECTION_CONTEXTS


def _dollar_substitution_token_is_implausible(token: str, delimiter: str) -> bool:
    stripped = token.strip().lower()
    if stripped in _SHELL_SPECIAL_PARAMETER_NAMES:
        return True
    if delimiter == "{":
        return not _BARE_SHELL_PARAMETER_NAME_RE.match(token.strip())
    return bool(_IMPLAUSIBLE_DOLLAR_PAREN_TOKEN_CHARS_RE.search(token))


def _dollar_substitution_pair_backtick_quoted(
    content: str, start: int, end: int
) -> bool:
    prefix_quoted = start > 0 and content[start - 1] == "`"
    suffix_quoted = end < len(content) and content[end] == "`"
    return prefix_quoted or suffix_quoted


def _dollar_substitution_pair_is_injection(match: re.Match, context: str) -> bool:
    content = match.string
    start, end = match.start(), match.end()
    if _dollar_substitution_pair_backtick_quoted(content, start, end):
        return False
    delimiter = content[start + 1]
    token = content[start + 2 : end - 1]
    if _dollar_substitution_token_is_implausible(token, delimiter):
        return True
    if _strong_sql_keyword_glued_to_pair(content, start, end):
        return False
    return context in _AMBIGUOUS_BACKTICK_INJECTION_CONTEXTS


def _quote_splice_token_is_dangerous_command(match: re.Match) -> bool:
    run = 0
    for fragment in re.split(r"['\"]+", match.group()):
        run = run + 1 if len(fragment) == 1 else 0
        if run >= 3:
            return True
    return False


_GLOB_WILDCARD_COMMAND_BOUNDARY_PREFIX_RE = re.compile(r"(?:;|\|\||\||&&|\$\(|`)\s*\Z")
_GLOB_WILDCARD_VALUE_START_CONTEXTS = frozenset({"request_body"})
_GLOB_WILDCARD_LETTER_RE = re.compile(r"[A-Za-z]")
_GLOB_WILDCARD_COMMAND_SUFFIX_CHARS = " \t\r\n;|&"


def _glob_wildcard_token_is_word_shaped(token: str) -> bool:
    for wildcard in _GLOB_WILDCARD_CHAR_RE.finditer(token):
        index = wildcard.start()
        left = 0
        position = index - 1
        while position >= 0 and _GLOB_WILDCARD_LETTER_RE.match(token, position):
            left += 1
            position -= 1
        right = 0
        position = index + 1
        while position < len(token) and _GLOB_WILDCARD_LETTER_RE.match(token, position):
            right += 1
            position += 1
        if left + right >= 2:
            return True
    return False


def _glob_wildcard_token_is_dangerous_command(
    match: re.Match, context: str = "unknown"
) -> bool:
    if not _glob_wildcard_token_is_word_shaped(match.group()):
        return False
    suffix = match.string[match.end() : match.end() + 1]
    if suffix and suffix not in _GLOB_WILDCARD_COMMAND_SUFFIX_CHARS:
        return False
    prefix = match.string[: match.start()]
    if _GLOB_WILDCARD_COMMAND_BOUNDARY_PREFIX_RE.search(prefix):
        return True
    if context in _GLOB_WILDCARD_VALUE_START_CONTEXTS:
        return not prefix.strip()
    return False


class _PickleOpcodePrefixResolutionBlocked(Exception):
    pass


class _PickleOpcodePrefixShortRead(Exception):
    pass


class _PickleOpcodePrefixUnpickler(pickle._Unpickler):
    stack: list[Any]
    metastack: list[Any]
    append: Callable[[Any], None]
    read: Callable[[int], bytes]
    readline: Callable[[], bytes]
    readinto: Callable[[bytearray], int]

    def find_class(self, module: str, name: str) -> Any:
        raise _PickleOpcodePrefixResolutionBlocked(module, name)

    def get_extension(self, code: int) -> Any:
        raise _PickleOpcodePrefixResolutionBlocked(code)

    def persistent_load(self, pid: Any) -> Any:
        raise _PickleOpcodePrefixResolutionBlocked(pid)


def _pickle_prefix_bounded_read(stream: io.BytesIO, size: int) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise _PickleOpcodePrefixShortRead(size)
    return data


def _pickle_prefix_bounded_readline(stream: io.BytesIO) -> bytes:
    line = stream.readline()
    if not line.endswith(b"\n"):
        raise _PickleOpcodePrefixShortRead(-1)
    return line


def _pickle_prefix_bounded_readinto(stream: io.BytesIO, buf: bytearray) -> int:
    count = stream.readinto(buf)
    if count != len(buf):
        raise _PickleOpcodePrefixShortRead(len(buf))
    return count


def _pickle_prefix_load_frame(unpickler: _PickleOpcodePrefixUnpickler) -> None:
    frame_size = int.from_bytes(unpickler.read(8), "little")
    if frame_size > sys.maxsize:
        raise ValueError(f"frame size > sys.maxsize: {frame_size}")


def _pickle_prefix_walk_from_start(
    window: bytes, is_complete_prefix: bool
) -> bool | None:
    total = len(window)
    stream = io.BytesIO(window)
    unpickler = _PickleOpcodePrefixUnpickler(stream)
    unpickler.stack = []
    unpickler.metastack = []
    unpickler.append = unpickler.stack.append
    unpickler.read = lambda size: _pickle_prefix_bounded_read(stream, size)
    unpickler.readline = lambda: _pickle_prefix_bounded_readline(stream)
    unpickler.readinto = lambda buf: _pickle_prefix_bounded_readinto(stream, buf)
    try:
        while stream.tell() < total:
            key = unpickler.read(1)
            if key[0] == pickle.FRAME[0]:
                _pickle_prefix_load_frame(unpickler)
                continue
            handler: Any = unpickler.dispatch.get(key[0])
            if handler is None:
                return False
            handler(unpickler)
    except _PickleOpcodePrefixShortRead:
        return False if is_complete_prefix else None
    except Exception:
        return False
    return True if is_complete_prefix else None


_PICKLE_SURROGATEESCAPE_LOW = 0xDC80
_PICKLE_SURROGATEESCAPE_HIGH = 0xDCFF


def _pickle_prefix_window_from_chars(chars: str) -> bytes | None:
    window = bytearray()
    for char in chars:
        code = ord(char)
        if code <= 0xFF:
            window.append(code)
        elif _PICKLE_SURROGATEESCAPE_LOW <= code <= _PICKLE_SURROGATEESCAPE_HIGH:
            window.append(code - _PICKLE_SURROGATEESCAPE_LOW + 0x80)
        else:
            return None
    return bytes(window)


def _pickle_opcode_scan_window(text: str, budget: int) -> tuple[bytes | None, bool]:
    is_complete = len(text) <= budget
    scan_slice = text if is_complete else text[:budget]
    return _pickle_prefix_window_from_chars(scan_slice), is_complete


def _pickle_global_prefix_is_opcode_stream(prefix: str) -> bool:
    if not prefix or prefix[-1] == "\n":
        return True
    window, is_complete = _pickle_opcode_scan_window(
        prefix, _PICKLE_OPCODE_WORK_BUDGET_BYTES
    )
    if window is None:
        return False
    return _pickle_prefix_walk_from_start(window, is_complete) is not False


_PICKLE_REDUCE_OR_BUILD_KEYS = frozenset({ord("R"), ord("b")})


def _pickle_suffix_walk_reaches_reduce_or_build(
    window: bytes, is_complete_suffix: bool
) -> bool | None:
    total = len(window)
    stream = io.BytesIO(window)
    unpickler = _PickleOpcodePrefixUnpickler(stream)
    unpickler.stack = [object()]
    unpickler.metastack = []
    unpickler.append = unpickler.stack.append
    unpickler.read = lambda size: _pickle_prefix_bounded_read(stream, size)
    unpickler.readline = lambda: _pickle_prefix_bounded_readline(stream)
    unpickler.readinto = lambda buf: _pickle_prefix_bounded_readinto(stream, buf)
    try:
        while stream.tell() < total:
            key = unpickler.read(1)
            if key[0] in _PICKLE_REDUCE_OR_BUILD_KEYS:
                return True
            if key[0] == pickle.FRAME[0]:
                _pickle_prefix_load_frame(unpickler)
                continue
            handler: Any = unpickler.dispatch.get(key[0])
            if handler is None:
                return False
            handler(unpickler)
    except _PickleOpcodePrefixShortRead:
        return False if is_complete_suffix else None
    except Exception:
        return False
    return False if is_complete_suffix else None


def _pickle_global_suffix_reaches_reduce_or_build(suffix: str) -> bool:
    window, is_complete = _pickle_opcode_scan_window(
        suffix, _PICKLE_OPCODE_WORK_BUDGET_BYTES
    )
    if window is None:
        return False
    return _pickle_suffix_walk_reaches_reduce_or_build(window, is_complete) is not False


def _pickle_global_candidate_is_injection(match: re.Match, _context: str) -> bool:
    if not _pickle_global_prefix_is_opcode_stream(match.string[: match.start()]):
        return False
    return _pickle_global_suffix_reaches_reduce_or_build(match.string[match.end(1) :])


_LOG4SHELL_JNDI_LOOKUP_RE = (
    r"(?i)\$\{(?:jndi:(?:ldap|rmi|dns)://"
    r"|\$?\{?(?:lower|upper):j\}ndi"
    r"|::-j\}ndi)"
)

ALWAYS_SCAN_HEADER_PATTERNS: frozenset[re.Pattern] = frozenset(
    {re.compile(_LOG4SHELL_JNDI_LOOKUP_RE)}
)


_LEGACY_IPV4_PART_RE = r"(?:0[xX][0-9a-fA-F]+|0[0-7]+|[1-9]\d*|0)"
_LEGACY_IPV4_HOST_RE = (
    r"://(?:[^/@\s]*@)?("
    + _LEGACY_IPV4_PART_RE
    + r"(?:\."
    + _LEGACY_IPV4_PART_RE
    + r"){0,3})(?=[:/\s]|$)"
)

_LEGACY_IPV4_BLOCKED_NETWORKS: tuple[ipaddress.IPv4Network, ...] = tuple(
    ipaddress.IPv4Network(cidr)
    for cidr in (
        "0.0.0.0/8",
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "100.100.100.200/32",
    )
)


def _decode_legacy_ipv4_part(part: str) -> int | None:
    if part.startswith(("0x", "0X")):
        digits = part[2:]
        return int(digits, 16) if digits else None
    if part.startswith("0") and len(part) > 1:
        digits = part[1:]
        return int(digits, 8) if all(ch in "01234567" for ch in digits) else None
    return int(part, 10) if part.isdigit() else None


_MIN_BARE_DECIMAL_LEGACY_IPV4 = 1 << 24


def _is_bare_decimal_legacy_ipv4_part(part: str) -> bool:
    return part == "0" or part[0] != "0"


def _is_ambiguous_bare_decimal_port(parts: list[str], decoded: list[int]) -> bool:
    if len(decoded) != 1 or decoded[0] == 0:
        return False
    is_small_value = decoded[0] < _MIN_BARE_DECIMAL_LEGACY_IPV4
    is_bare_decimal = _is_bare_decimal_legacy_ipv4_part(parts[0])
    return is_small_value and is_bare_decimal


def _decode_legacy_ipv4_host(host: str) -> int | None:
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    decoded: list[int] = []
    for part in parts:
        value = _decode_legacy_ipv4_part(part)
        if value is None:
            return None
        decoded.append(value)
    if _is_ambiguous_bare_decimal_port(parts, decoded):
        return None
    for value in decoded[:-1]:
        if value > 255:
            return None
    remaining_bits = 8 * (5 - len(decoded))
    if decoded[-1] >= (1 << remaining_bits):
        return None
    result = 0
    for value in decoded[:-1]:
        result = (result << 8) | value
    return (result << remaining_bits) | decoded[-1]


def _is_blocked_legacy_ipv4(ip_int: int) -> bool:
    address = ipaddress.IPv4Address(ip_int)
    return any(address in network for network in _LEGACY_IPV4_BLOCKED_NETWORKS)


def _legacy_ipv4_match_is_blocked(match: re.Match) -> bool:
    ip_int = _decode_legacy_ipv4_host(match.group(1))
    return ip_int is not None and _is_blocked_legacy_ipv4(ip_int)


def _ldap_breakout_backward_window(
    text: str, close_paren_pos: int
) -> tuple[str, int, bool]:
    depth = 0
    backward_start = max(0, close_paren_pos - _LDAP_BREAKOUT_LOCAL_SCAN_CHARS)
    position = close_paren_pos - 1
    while (
        position >= backward_start
        and text[position] not in _LDAP_BREAKOUT_BACKWARD_BOUNDARY_CHARS
    ):
        if text[position] == ")":
            depth -= 1
        elif text[position] == "(":
            depth += 1
        position -= 1
    backward_window = text[position + 1 : close_paren_pos]
    depth_unresolved = backward_start > 0 and position < backward_start
    return backward_window, depth, depth_unresolved


def _ldap_next_candidate_scan_limit(match: re.Match, after: int) -> int:
    next_match = match.re.search(match.string, after)
    return next_match.end() if next_match else len(match.string)


def _ldap_filter_expression_forward_extent(
    text: str, start: int, scan_limit: int
) -> int:
    position = start
    depth = 0
    while True:
        boundary = _LDAP_FILTER_EXPRESSION_STRUCTURE_RE.search(
            text, position, scan_limit
        )
        if boundary is None:
            return scan_limit
        char = boundary.group()
        if char in _LDAP_BREAKOUT_FORWARD_BOUNDARY_CHARS:
            return boundary.start()
        if char == "(":
            depth += 1
        elif depth == 0:
            return boundary.start()
        else:
            depth -= 1
        position = boundary.end()


def _ldap_breakout_forward_window(match: re.Match, close_paren_pos: int) -> str:
    text: str = match.string
    scan_limit = _ldap_next_candidate_scan_limit(match, match.end())
    extent = _ldap_filter_expression_forward_extent(
        text, close_paren_pos + 1, scan_limit
    )
    return text[close_paren_pos:extent]


def _ldap_wildcard_chain_is_injection(match: re.Match) -> bool:
    text = match.string
    close_paren_pos = match.start() + match.group().index(")")

    backward_window, depth, depth_unresolved = _ldap_breakout_backward_window(
        text, close_paren_pos
    )
    forward_window = _ldap_breakout_forward_window(match, close_paren_pos)

    wildcard_adjacent = match.group().startswith("*")
    depth_proves_breakout = depth <= 0 and (wildcard_adjacent or not depth_unresolved)
    depth_or_wildcard_clause = depth_proves_breakout or bool(
        _LDAP_BREAKOUT_WILDCARD_CLAUSE_END_RE.search(backward_window)
    )
    if not depth_or_wildcard_clause:
        return False
    return bool(
        _LDAP_BREAKOUT_ATTACK_TOKEN_RE.search(backward_window)
        or _LDAP_BREAKOUT_ATTACK_TOKEN_RE.search(forward_window)
    )


def _ldap_paren_conjunction_is_injection(match: re.Match) -> bool:
    text = match.string
    scan_limit = _ldap_next_candidate_scan_limit(match, match.end())
    tail_end = _ldap_filter_expression_forward_extent(text, match.end(), scan_limit)
    tail = text[match.end() : tail_end]
    if _LDAP_PAREN_CONJUNCTION_FOLLOWUP_SYMBOL_RE.match(tail):
        return True
    return "=" in tail and bool(_LDAP_PAREN_CONJUNCTION_FOLLOWUP_ATTR_RE.match(tail))


DETECTION_CATEGORY_WEIGHTS: dict[str, float] = {
    category: 1.0 for category in ALL_DETECTION_CATEGORIES
}

DETECTION_PATTERN_WEIGHT_OVERRIDES: dict[str, float] = {
    _SELECT_FROM_RE: 0.5,
    _SELECT_STAR_RE: 0.5,
    _WHERE_CLAUSE_RE: 0.5,
}


def _resolve_pattern_weight(pattern: str, category: str) -> float:
    if pattern in DETECTION_PATTERN_WEIGHT_OVERRIDES:
        return DETECTION_PATTERN_WEIGHT_OVERRIDES[pattern]
    return DETECTION_CATEGORY_WEIGHTS.get(category, 1.0)


def _regex_anomaly(regex_threats: list[dict[str, Any]]) -> float:
    return float(sum(t.get("weight", 1.0) for t in regex_threats))


_DECODE_BUDGET_EXHAUSTED_PATTERN = "decode_budget_exhausted"


def _decode_budget_exhausted_threat() -> dict[str, Any]:
    return {
        "type": "regex",
        "pattern": _DECODE_BUDGET_EXHAUSTED_PATTERN,
        "match": _DECODE_BUDGET_EXHAUSTED_PATTERN,
        "position": 0,
        "execution_time": 0.0,
        "category": "custom",
        "weight": _resolve_pattern_weight(_DECODE_BUDGET_EXHAUSTED_PATTERN, "custom"),
    }


def _pattern_excluded_from_view(
    pattern: re.Pattern,
    raw_view_only: bool | None,
    url_decoded_view_only: bool | None = None,
) -> bool:
    is_raw_view_pattern = pattern.pattern in DETECTION_RAW_VIEW_PATTERN_SOURCES
    is_url_decoded_view_pattern = (
        pattern.pattern in DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES
    )
    if raw_view_only is True:
        return is_url_decoded_view_pattern or not is_raw_view_pattern
    if url_decoded_view_only is True:
        return is_raw_view_pattern or not is_url_decoded_view_pattern
    if raw_view_only is False:
        return is_raw_view_pattern or is_url_decoded_view_pattern
    return False


def _pattern_should_be_skipped(
    pattern: re.Pattern,
    contexts: frozenset[str],
    category: str,
    *,
    raw_view_only: bool | None,
    skip_filter: bool,
    normalized_context: str,
    enabled_categories: set[str] | None,
    url_decoded_view_only: bool | None = None,
) -> bool:
    if _pattern_excluded_from_view(pattern, raw_view_only, url_decoded_view_only):
        return True
    if not skip_filter and normalized_context not in contexts:
        return True
    return (
        enabled_categories is not None
        and category != "custom"
        and category not in enabled_categories
    )


_CANDIDATE_REJECTION_VALIDATORS: tuple[
    tuple[str, Callable[[re.Match, str], bool]], ...
] = (
    (_LEGACY_IPV4_HOST_RE, lambda m, _c: _legacy_ipv4_match_is_blocked(m)),
    (_LDAP_WILDCARD_CHAIN_RE, lambda m, _c: _ldap_wildcard_chain_is_injection(m)),
    (_LDAP_WILDCARD_EQUALS_RE, lambda m, _c: _ldap_wildcard_chain_is_injection(m)),
    (_LDAP_PAREN_BREAKOUT_RE, lambda m, _c: _ldap_wildcard_chain_is_injection(m)),
    (
        _LDAP_PAREN_CONJUNCTION_RE,
        lambda m, _c: _ldap_paren_conjunction_is_injection(m),
    ),
    (_GLUED_BACKTICK_CANDIDATE_RE, _glued_backtick_pair_is_injection),
    (_GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE, _dollar_substitution_pair_is_injection),
    (
        _BRACE_EXPANSION_COMMAND_RE,
        lambda m, _c: _brace_expansion_is_dangerous_command(m),
    ),
    (
        _QUOTE_SPLICE_CANDIDATE_RE,
        lambda m, _c: _quote_splice_token_is_dangerous_command(m),
    ),
    (
        _GLOB_WILDCARD_ATOM_RE,
        _glob_wildcard_token_is_dangerous_command,
    ),
    (_DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE, _pickle_global_candidate_is_injection),
)


_WINDOWED_PATTERN_FINDERS: dict[str, Callable[[str], Iterator[re.Match]]] = {
    _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE: lambda text: (
        _cmd_injection_shell_dash_c_finditer(
            text, _CMD_INJECTION_NEWLINE_SHELL_DASH_C_COMPILED_RE
        )
    ),
    _LDAP_NULL_BYTE_ATTR_RE: lambda text: _ldap_null_byte_attr_finditer(
        text, _LDAP_NULL_BYTE_ATTR_COMPILED_RE, _LDAP_NULL_BYTE_TAIL_RE
    ),
    _LDAP_NULL_BYTE_DECODED_ATTR_RE: lambda text: _ldap_null_byte_attr_finditer(
        text,
        _LDAP_NULL_BYTE_DECODED_ATTR_COMPILED_RE,
        _LDAP_NULL_BYTE_DECODED_TAIL_RE,
    ),
    _QUOTE_SPLICE_CANDIDATE_RE: lambda text: _quote_splice_finditer(
        text, _QUOTE_SPLICE_CANDIDATE_COMPILED_RE
    ),
}

_SCAN_WINDOW_BOUND_SOURCES: dict[str, tuple[tuple[str, str], ...]] = {
    r"<script[^>]*>[^<]*<\/script\s*>": ((r"<script", r"<\/script\s*>"),),
    (
        r"(?:<[A-Za-z/][^<>]*style\s*=\s{0,20}[\"']?[^<>\"']*"
        r"(?:expression|behavior|url)\s*\([^)]*\))"
    ): ((r"<[A-Za-z/][^<>]*style\s*=", r"\)"),),
    r"(?:<object[^>]*>[\s\S]*<\/object\s*>)": ((r"<object", r"<\/object\s*>"),),
    r"(?:<embed[^>]*>[\s\S]*<\/embed\s*>)": ((r"<embed", r"<\/embed\s*>"),),
    r"(?:<applet[^>]*>[\s\S]*<\/applet\s*>)": ((r"<applet", r"<\/applet\s*>"),),
    r"\.\.;[^/\\]*[/\\]": ((r"\.\.;", r"[/\\]"),),
    (
        r"=(?:https?|ftp):\/\/[^\s'\"<>]+\/[^\s'\"<>\/]*"
        r"\.(?:phtml|php[3-5]?|phar|jsp|aspx?|cgi|pl|py|sh|txt|inc)(?![a-zA-Z0-9])"
    ): (
        (
            r"=(?:https?|ftp):\/\/",
            r"\.(?:phtml|php\d*|phar|jsp|aspx?|cgi|pl|py|sh|txt|inc)[a-zA-Z0-9]*",
        ),
    ),
    r"<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>": ((r"<!(?:ENTITY|DOCTYPE)", r">"),),
    r"(?:<!\[CDATA\[.*?\]\]>)": ((r"<!\[CDATA\[", r"\]\]>"),),
    r"<!DOCTYPE[^>\[]*\[[\s\S]*?<!ENTITY": ((r"<!DOCTYPE", r"<!ENTITY"),),
    _SSTI_HASH_BRACE_SHAPE_RE: ((r"#\{", r"\}"),),
}

_SCAN_WINDOW_PATTERNS: dict[str, tuple[tuple[re.Pattern, re.Pattern], ...]] = {
    source: tuple(
        (re.compile(prefix, re.IGNORECASE), re.compile(terminator, re.IGNORECASE))
        for prefix, terminator in pairs
    )
    for source, pairs in _SCAN_WINDOW_BOUND_SOURCES.items()
}


def _iter_scan_window_matches(
    content: str,
    pattern: re.Pattern,
    bounds: tuple[tuple[re.Pattern, re.Pattern], ...],
) -> Iterator[re.Match]:
    for prefix, terminator in bounds:
        yield from bounded_finditer(content, pattern, prefix, terminator)


def _sanitize_for_reporting(value: str) -> str:
    return value.encode("utf-8", errors="surrogateescape").decode(
        "utf-8", errors="backslashreplace"
    )


def _build_regex_threat(
    pattern: re.Pattern,
    match: re.Match,
    category: str,
    pattern_start: float,
    context: str = "unknown",
) -> dict[str, Any] | None:
    for candidate, is_valid_threat in _CANDIDATE_REJECTION_VALIDATORS:
        if pattern.pattern == candidate and not is_valid_threat(match, context):
            return None
    return {
        "type": "regex",
        "pattern": pattern.pattern,
        "match": _sanitize_for_reporting(match.group()),
        "position": match.start(),
        "execution_time": time.monotonic() - pattern_start,
        "category": category,
        "weight": _resolve_pattern_weight(pattern.pattern, category),
    }


def _build_timeout_threat(
    pattern: re.Pattern, category: str, pattern_start: float
) -> dict[str, Any]:
    return {
        "type": "pattern_timeout",
        "pattern": pattern.pattern,
        "match": "",
        "position": 0,
        "execution_time": time.monotonic() - pattern_start,
        "category": category,
        "weight": _resolve_pattern_weight(pattern.pattern, category),
    }


def _first_accepted_regex_threat(
    matches: Iterator[re.Match],
    pattern: re.Pattern,
    category: str,
    pattern_start: float,
    context: str = "unknown",
) -> dict[str, Any] | None:
    for match in matches:
        threat = _build_regex_threat(pattern, match, category, pattern_start, context)
        if threat:
            return threat
    return None


class _DetectionState(NamedTuple):
    compiler: PatternCompiler | None
    preprocessor: ContentPreprocessor | None
    semantic_analyzer: SemanticAnalyzer | None
    performance_monitor: PerformanceMonitor | None
    semantic_threshold: float
    threat_score_threshold: float


_LEGACY_DETECTION_STATE = _DetectionState(
    compiler=None,
    preprocessor=None,
    semantic_analyzer=None,
    performance_monitor=None,
    semantic_threshold=0.7,
    threat_score_threshold=1.0,
)


def _build_enhanced_detection_state(config: Any) -> _DetectionState:
    return _DetectionState(
        compiler=PatternCompiler(
            default_timeout=config.detection_compiler_timeout,
            max_cache_size=config.detection_max_tracked_patterns,
        ),
        preprocessor=ContentPreprocessor(
            max_content_length=config.detection_max_content_length,
            preserve_attack_patterns=config.detection_preserve_attack_patterns,
            max_full_scan_bytes=config.detection_max_body_inspect_bytes,
        ),
        semantic_analyzer=SemanticAnalyzer(),
        performance_monitor=PerformanceMonitor(
            anomaly_threshold=config.detection_anomaly_threshold,
            slow_pattern_threshold=config.detection_slow_pattern_threshold,
            history_size=config.detection_monitor_history_size,
            max_tracked_patterns=config.detection_max_tracked_patterns,
            anomaly_emission_cooldown=config.detection_anomaly_emission_cooldown,
            min_samples_for_anomaly=config.detection_min_samples_for_anomaly,
        ),
        semantic_threshold=config.detection_semantic_threshold,
        threat_score_threshold=config.detection_threat_score_threshold,
    )


_HTML_EVENT_HANDLER_ATTRS_PROVENANCE = (
    "re-derived 2026-08-20 as the union of two actively pentested, "
    "regularly-updated XSS references rather than a one-time reading of "
    "spec text: every event handler id in PortSwigger's XSS cheat sheet "
    "(https://portswigger.net/web-security/cross-site-scripting/cheat-"
    "sheet, 142 names, includes vendor-prefixed and experimental handlers "
    "such as onwebkitfullscreenchange and onpagereveal, plus "
    "onafterscriptexecute/onbeforescriptexecute missed by the first "
    "extraction pass and added in a later adversarial review) union every "
    "handler in OWASP's XSS Filter Evasion Cheat Sheet (https://"
    "cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_"
    "Sheet.html, 102 names, includes legacy IE/DHTML-only handlers such "
    "as onbounce and onrowsenter), both extracted verbatim from the live "
    "page's markup, not summarized; this still goes silently stale every "
    "time either source adds a handler this list has not re-absorbed, no "
    "test fails when it does, only recall quietly drops, so it needs "
    "periodic re-derivation against the then-current sources, not a "
    "one-time fix. Deliberately excluded despite resembling a handler: "
    "onpointerlockchange/onpointerlockerror (real Document IDL "
    "properties per the Pointer Lock spec, but confirmed unreflected as "
    "an HTML content attribute in a live Chromium build, so an inline "
    "`<div onpointerlockchange=...>` payload never executes and neither "
    "cheat sheet lists it); oncustomthing and other invented on*-prefixed "
    "words are excluded because they are not handlers at all"
)
_HTML_EVENT_HANDLER_ATTRS = frozenset(
    {
        "onabort",
        "onactivate",
        "onafterprint",
        "onafterscriptexecute",
        "onafterupdate",
        "onanimationcancel",
        "onanimationend",
        "onanimationiteration",
        "onanimationstart",
        "onauxclick",
        "onbeforeactivate",
        "onbeforecopy",
        "onbeforecut",
        "onbeforedeactivate",
        "onbeforeeditfocus",
        "onbeforeinput",
        "onbeforematch",
        "onbeforepaste",
        "onbeforeprint",
        "onbeforescriptexecute",
        "onbeforetoggle",
        "onbeforeunload",
        "onbeforeupdate",
        "onbegin",
        "onblur",
        "onbounce",
        "oncancel",
        "oncanplay",
        "oncanplaythrough",
        "oncellchange",
        "onchange",
        "onclick",
        "onclose",
        "oncommand",
        "oncontentvisibilityautostatechange",
        "oncontextlost",
        "oncontextmenu",
        "oncontextrestored",
        "oncontrolselect",
        "oncopy",
        "oncuechange",
        "oncut",
        "ondataavailable",
        "ondatasetchanged",
        "ondatasetcomplete",
        "ondblclick",
        "ondeactivate",
        "ondevicemotion",
        "ondeviceorientation",
        "ondrag",
        "ondragdrop",
        "ondragend",
        "ondragenter",
        "ondragexit",
        "ondragleave",
        "ondragover",
        "ondragstart",
        "ondrop",
        "ondurationchange",
        "onemptied",
        "onend",
        "onended",
        "onerror",
        "onerrorupdate",
        "onfilterchange",
        "onfinish",
        "onfocus",
        "onfocusin",
        "onfocusout",
        "onformdata",
        "onfullscreenchange",
        "ongesturechange",
        "ongestureend",
        "ongesturestart",
        "ongotpointercapture",
        "onhashchange",
        "onhelp",
        "oninput",
        "oninvalid",
        "onkeydown",
        "onkeypress",
        "onkeyup",
        "onlanguagechange",
        "onlayoutcomplete",
        "onload",
        "onloadeddata",
        "onloadedmetadata",
        "onloadstart",
        "onlocation",
        "onlosecapture",
        "onlostpointercapture",
        "onmediacomplete",
        "onmediaerror",
        "onmessage",
        "onmessageerror",
        "onmousedown",
        "onmouseenter",
        "onmouseleave",
        "onmousemove",
        "onmouseout",
        "onmouseover",
        "onmouseup",
        "onmousewheel",
        "onmove",
        "onmoveend",
        "onmovestart",
        "onmozfullscreenchange",
        "onoffline",
        "ononline",
        "onoutofsync",
        "onpagehide",
        "onpagereveal",
        "onpageshow",
        "onpageswap",
        "onpaste",
        "onpause",
        "onplay",
        "onplaying",
        "onpointercancel",
        "onpointerdown",
        "onpointerenter",
        "onpointerleave",
        "onpointermove",
        "onpointerout",
        "onpointerover",
        "onpointerrawupdate",
        "onpointerup",
        "onpopstate",
        "onprogress",
        "onpromptaction",
        "onpromptdismiss",
        "onpropertychange",
        "onratechange",
        "onreadystatechange",
        "onredo",
        "onrejectionhandled",
        "onrepeat",
        "onreset",
        "onresize",
        "onresizeend",
        "onresizestart",
        "onresume",
        "onreverse",
        "onrowdelete",
        "onrowexit",
        "onrowinserted",
        "onrowsenter",
        "onscroll",
        "onscrollend",
        "onscrollsnapchange",
        "onscrollsnapchanging",
        "onsearch",
        "onsecuritypolicyviolation",
        "onseek",
        "onseeked",
        "onseeking",
        "onselect",
        "onselectionchange",
        "onselectstart",
        "onslotchange",
        "onstalled",
        "onstart",
        "onstop",
        "onstorage",
        "onsubmit",
        "onsuspend",
        "onsyncrestored",
        "ontimeerror",
        "ontimeupdate",
        "ontoggle",
        "ontouchcancel",
        "ontouchend",
        "ontouchmove",
        "ontouchstart",
        "ontrackchange",
        "ontransitioncancel",
        "ontransitionend",
        "ontransitionrun",
        "ontransitionstart",
        "onundo",
        "onunhandledrejection",
        "onunload",
        "onurlflip",
        "onvalidationstatuschange",
        "onvolumechange",
        "onwaiting",
        "onwebkitanimationend",
        "onwebkitanimationiteration",
        "onwebkitanimationstart",
        "onwebkitfullscreenchange",
        "onwebkitmouseforcechanged",
        "onwebkitmouseforcedown",
        "onwebkitmouseforceup",
        "onwebkitmouseforcewillbegin",
        "onwebkitneedkey",
        "onwebkitplaybacktargetavailabilitychanged",
        "onwebkitpresentationmodechanged",
        "onwebkittransitionend",
        "onwebkitwillrevealbottom",
        "onwheel",
    }
)
_HTML_EVENT_HANDLER_ALTERNATION = "|".join(
    re.escape(name)
    for name in sorted(_HTML_EVENT_HANDLER_ATTRS, key=lambda c: (-len(c), c))
)


class SusPatternsManager:
    _instance = None
    _config = None

    _pattern_definitions: list[tuple[str, frozenset[str], str]] = [
        (r"<script[^>]*>[^<]*<\/script\s*>", _CTX_XSS, "xss"),
        (r"javascript:\s*[^\s]+", _CTX_XSS, "xss"),
        (_XSS_JS_SCHEME_CTRL_CHAR_RE, _CTX_XSS, "xss"),
        (
            r"(?:"
            + _HTML_TAG_OPEN_RE
            + r"(?:[^<>]*[^<>\s/])?(?<!=)(?<!=\")(?<!=')[\s/]+(?:"
            + _HTML_EVENT_HANDLER_ALTERNATION
            + r")\s*="
            + _ATTR_EQUALS_WHITESPACE_RE
            + r"(?:[\"'][^\"']*[\"']|[^\s>]+))",
            _CTX_XSS,
            "xss",
        ),
        (
            r"(?:"
            + _HTML_TAG_OPEN_RE
            + r"(?:[^<>]*[^<>\s])?\s+(?:href|src|data|action)\s*=[\s\"\']*"
            r"(?:javascript|vbscript|data):)",
            _CTX_XSS,
            "xss",
        ),
        (
            r"(?:"
            + _HTML_TAG_OPEN_RE
            + r"[^<>]*style\s*="
            + _ATTR_EQUALS_WHITESPACE_RE
            + r"[\"']?[^<>\"']*(?:expression|behavior|url)\s*\("
            r"[^)]*\))",
            _CTX_XSS,
            "xss",
        ),
        (r"(?:<object[^>]*>[\s\S]*<\/object\s*>)", _CTX_XSS, "xss"),
        (r"(?:<embed[^>]*>[\s\S]*<\/embed\s*>)", _CTX_XSS, "xss"),
        (r"(?:<applet[^>]*>[\s\S]*<\/applet\s*>)", _CTX_XSS, "xss"),
        (_SELECT_FROM_RE, _CTX_SQLI, "sqli"),
        (_SELECT_STAR_RE, _CTX_SQLI, "sqli"),
        (_WHERE_CLAUSE_RE, _CTX_SQLI, "sqli"),
        (_SQLI_TAUTOLOGY_RE, _CTX_SQLI, "sqli"),
        (r"(?i)UNION\s+(?:ALL\s+)?SELECT", _CTX_SQLI, "sqli"),
        (
            r"(?i)('\s*(?:OR|AND)\s*[\(\s]*'?(?:[@:$][A-Za-z_]\w*|[\d\w]+)\s*"
            r"(?:=|LIKE|<|>|<=|>=)\s*[\(\s]*'?(?:[@:$][A-Za-z_]\w*|[\d\w]+))",
            _CTX_SQLI,
            "sqli",
        ),
        (
            r"(?i)(UNION\s+(?:ALL\s+)?SELECT\s+NULL(?:[,\s]*NULL)*[,\s]*|"
            r"\(\s*SELECT\s+(?:@@|VERSION))",
            _CTX_SQLI,
            "sqli",
        ),
        (r"(?i)(?:INTO\s+(?:OUTFILE|DUMPFILE)\s+'[^']+')", _CTX_SQLI, "sqli"),
        (_SQLI_LOAD_FILE_RE, _CTX_SQLI, "sqli"),
        (r"(?i)(?:BENCHMARK\s*\(\s*\d+\s*,)", _CTX_SQLI, "sqli"),
        (r"(?i)(?:SLEEP\s*\(\s*\d+\s*\))", _CTX_SQLI, "sqli"),
        (
            r"(?i)(?:\/\*![0-9]*\s*(?:OR|AND|UNION|SELECT|INSERT|DELETE|DROP|"
            r"CONCAT|CHAR|UPDATE)\b)",
            _CTX_SQLI,
            "sqli",
        ),
        (r"\w/\*(?!!)[^*]*\*/\w", _CTX_SQLI, "sqli"),
        (
            r"(?i)(?:OR|AND)\s+(?:'[\w\d]*'='[\w\d]*'?|"
            r"[@:$][A-Za-z_]\w*\s*=\s*[@:$][A-Za-z_]\w*)",
            _CTX_SQLI,
            "sqli",
        ),
        (
            r"(?i);\s*(?:DROP|TRUNCATE|ALTER|CREATE)\s+(?:TABLE|DATABASE|SCHEMA)\b",
            _CTX_SQLI,
            "sqli",
        ),
        (
            r"(?i);\s*(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|"
            r"SELECT\b[^;]*?\bFROM\b|REPLACE\s+INTO)\b",
            _CTX_SQLI,
            "sqli",
        ),
        (
            r"(?i)\bEXEC(?:UTE)?\s+(?:xp_\w+|sp_\w+)",
            _CTX_SQLI,
            "sqli",
        ),
        (_SQLI_ORDER_BY_TERMINATOR_RE, _CTX_SQLI, "sqli"),
        (_SQLI_COMMENT_TERMINATOR_RE, _CTX_SQLI, "sqli"),
        (r"(?:\.\.\/|\.\.\\)(?:\.\.\/|\.\.\\)+", _CTX_DIR_TRAVERSAL, "dir_traversal"),
        (_DIR_TRAVERSAL_ETC_SENSITIVE_RE, _CTX_DIR_TRAVERSAL, "dir_traversal"),
        (_DIR_TRAVERSAL_WINDOWS_INI_RE, _CTX_DIR_TRAVERSAL, "dir_traversal"),
        (_DIR_TRAVERSAL_PROC_ENVIRON_RE, _CTX_DIR_TRAVERSAL, "dir_traversal"),
        (_DIR_TRAVERSAL_VAR_LOG_RE, _CTX_DIR_TRAVERSAL, "dir_traversal"),
        (_PATH_TRAVERSAL_SEMICOLON_SEP_RE, _CTX_DIR_TRAVERSAL, "dir_traversal"),
        (
            r";\s*(?:ls|cat|rm|chmod|chown|wget|curl|nc|netcat|ping|telnet)\s+"
            r"-[a-zA-Z]+\s+",
            _CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        (
            r"\|\s*(?:wget|curl|fetch|lwp-download|lynx|links|GET)\s+",
            _CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        (
            _CMD_INJECTION_DOLLAR_SUBSTITUTION_RE,
            _CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        (
            r"\A\s*(?:[;&|]\s*)*`\s*(?:[A-Za-z0-9_./~]|\$[({])"
            r"(?:[^`\\\n]|\\.)*\s*`"
            r"(?:\s*[;&|]\s*`\s*(?:[A-Za-z0-9_./~]|\$[({])(?:[^`\\\n]|\\.)*\s*`)*"
            r"\s*(?:[;&|]\s*)*\Z",
            _CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        (
            _GLUED_BACKTICK_CANDIDATE_RE,
            _CTX_CMD_INJECTION_WITH_URL_PATH,
            "cmd_injection",
        ),
        (
            _GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE,
            _CTX_CMD_INJECTION_WITH_URL_PATH,
            "cmd_injection",
        ),
        (
            _LOG4SHELL_JNDI_LOOKUP_RE,
            _CTX_LOG4SHELL,
            "cmd_injection",
        ),
        (
            _CMD_INJECTION_SHELL_DASH_FLAG_RE,
            _CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        (
            r"(?:\A|[;|&])\s*[^=\s;|&]+=[^\s;|&]+\s+(?:/?(?:[\w.-]+/)*env\s+)?/?(?:[\w.-]+/)*"
            r"(?:bash|sh|ksh|csh|tsch|zsh|ash)\s+-[a-zA-Z]+",
            _CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        (
            _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE,
            _CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        (
            r"\b(?:eval|system|exec|shell_exec|passthru|popen|proc_open|create_function)\s*\(",
            _CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        (
            _CMD_INJECTION_NODE_CHILD_PROCESS_RE,
            _CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        (
            _CMD_INJECTION_PHP_ASSERT_VARIABLE_RE,
            _CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        (
            _CMD_INJECTION_PYTHON_EXEC_FAMILY_RE,
            _CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        (
            _JS_DYNAMIC_EVAL_FUNCTION_CTOR_RE,
            _CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        (
            _JS_DYNAMIC_EVAL_BRACKET_RE,
            _CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        (
            _JS_DYNAMIC_EVAL_CTOR_GADGET_RE,
            _CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        (
            _JS_DYNAMIC_EVAL_TIMER_STRING_ARG_RE,
            _CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        (
            r"[;|&]\s*(?:ls|cat|rm|id|whoami|uname|wget|curl|nc|netcat|socat|bash|sh|python|perl)\b",
            _CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        (
            r"(?i)\b(?:nc|netcat|ncat)\s+-[a-z]*e\b|/dev/tcp/\d",
            _CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        (
            _BRACE_EXPANSION_COMMAND_RE,
            _CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        (
            _QUOTE_SPLICE_CANDIDATE_RE,
            _CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        (
            _GLOB_WILDCARD_ATOM_RE,
            _CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        (
            r"(?:php|data|zip|rar|file|glob|expect|input|phpinfo|zlib|phar|ssh2|"
            r"rar|ogg|expect)://[^\s]+",
            _CTX_FILE_INCLUSION,
            "file_inclusion",
        ),
        (
            _FILE_INCLUSION_BARE_HOST_RE,
            _CTX_FILE_INCLUSION,
            "file_inclusion",
        ),
        (
            r"=(?:https?|ftp):\/\/[^\s'\"<>]+\/[^\s'\"<>\/]*\.(?:phtml|php[3-5]?|"
            r"phar|jsp|aspx?|cgi|pl|py|sh|txt|inc)(?![a-zA-Z0-9])",
            _CTX_FILE_INCLUSION,
            "file_inclusion",
        ),
        (
            _FILE_INCLUSION_JSON_VALUE_RE,
            _CTX_FILE_INCLUSION,
            "file_inclusion",
        ),
        (r"\(\s*[|&]\s*\(\s*[^)(]+=[*]", _CTX_LDAP, "ldap"),
        (_LDAP_WILDCARD_EQUALS_RE, _CTX_LDAP, "ldap"),
        (_LDAP_PAREN_BREAKOUT_RE, _CTX_LDAP, "ldap"),
        (_LDAP_PAREN_CONJUNCTION_RE, _CTX_LDAP, "ldap"),
        (_LDAP_WILDCARD_CHAIN_RE, _CTX_LDAP, "ldap"),
        (_LDAP_NULL_BYTE_ATTR_RE, _CTX_LDAP, "ldap"),
        (_LDAP_NULL_BYTE_BARE_RE, _CTX_LDAP, "ldap"),
        (_LDAP_NULL_BYTE_DECODED_ATTR_RE, _CTX_LDAP, "ldap"),
        (_LDAP_NULL_BYTE_DECODED_BARE_RE, _CTX_LDAP, "ldap"),
        (r"<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>", _CTX_XML, "xml"),
        (_XML_XXE_PUBLIC_EXTERNAL_DTD_RE, _CTX_XML, "xml"),
        (r"(?:<!\[CDATA\[.*?\]\]>)", _CTX_XML, "xml"),
        (r"<!DOCTYPE[^>\[]*\[[\s\S]*?<!ENTITY", _CTX_XML, "xml"),
        (
            r"(?:^|\s|/)(?:(?<=://)[^\s/@]*@)?(?:localhost\.?|127\.0\.0\.1|0\.0\.0\.0|"
            r"\[::(?:\d*)\]|\[::ffff:127\.0\.0\.1\]|169\.254(?:\.\d{1,3}){2}|"
            r"192\.168(?:\.\d{1,3}){2}|"
            r"10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2[0-9]|3[01])(?:\.\d{1,3}){2}|"
            r"metadata\.google\.internal|metadata\.goog|100\.100\.100\.200)"
            r"(?::\d+)?(?:\s|$|/)",
            _CTX_SSRF,
            "ssrf",
        ),
        (_LEGACY_IPV4_HOST_RE, _CTX_SSRF, "ssrf"),
        (r"(?:file|dict|gopher|jar|tftp)://[^\s]+", _CTX_SSRF, "ssrf"),
        (r"://[^/\s@]*@[^/\s@]*@", _CTX_SSRF, "ssrf"),
        (_SSRF_BARE_METADATA_ALIAS_RE, _CTX_SSRF, "ssrf"),
        (
            r"\{\s*\$(?:where|gt|lt|ne|eq|regex|in|nin|all|size|exists|type|mod|"
            r"options):",
            _CTX_NOSQL,
            "nosql",
        ),
        (r"(?:\{\s*\$[a-zA-Z]+\s*:\s*(?:\{|\[))", _CTX_NOSQL, "nosql"),
        (
            r'"\$(?:where|regex|expr|jsonSchema|function|accumulator|type|exists|size)"\s*:',
            _CTX_NOSQL,
            "nosql",
        ),
        (
            r'"\$(?:gt|gte|lt|lte|ne|eq|in|nin|all|mod)"' r'\s*:\s*(?:""|null|\{|\[)',
            _CTX_NOSQL,
            "nosql",
        ),
        (
            r'"[^"]+"\s*:\s*\{\s*"\$(?:ne|eq)"\s*:\s*(?:true|false)',
            _CTX_NOSQL,
            "nosql",
        ),
        (
            r"\[\$(?:where|gt|gte|lt|lte|ne|eq|regex|in|nin|nor|and|or|not|all|"
            r"size|exists|type|mod|options|expr|function|elemMatch)\]",
            _CTX_NOSQL,
            "nosql",
        ),
        (
            _FILE_UPLOAD_FILENAME_EQUALS_RE
            + r"[\"'][^\"']*\.(?:"
            + _FILE_UPLOAD_DANGEROUS_EXT_ALTERNATION
            + r")[\"\']",
            _CTX_FILE_UPLOAD,
            "file_upload",
        ),
        (
            _FILE_UPLOAD_DOUBLE_EXTENSION_RE,
            _CTX_FILE_UPLOAD,
            "file_upload",
        ),
        (
            _FILE_UPLOAD_TRUNCATION_RE,
            _CTX_FILE_UPLOAD,
            "file_upload",
        ),
        (
            _FILE_UPLOAD_DECODED_TRUNCATION_RE,
            _CTX_FILE_UPLOAD,
            "file_upload",
        ),
        (_PATH_TRAVERSAL_ENCODED_DOT_RE, _CTX_PATH_TRAVERSAL, "path_traversal"),
        (
            _TEMPLATE_CURLY_KEYWORD_RE,
            _CTX_TEMPLATE,
            "template",
        ),
        (
            _TEMPLATE_PERCENT_KEYWORD_RE,
            _CTX_TEMPLATE,
            "template",
        ),
        (
            _TEMPLATE_ASP_KEYWORD_RE,
            _CTX_TEMPLATE,
            "template",
        ),
        (
            _TEMPLATE_DOLLAR_BRACE_CALL_RE,
            _CTX_TEMPLATE,
            "template",
        ),
        (
            _TEMPLATE_CURLY_CALL_RE,
            _CTX_TEMPLATE,
            "template",
        ),
        (_SSTI_HASH_BRACE_SHAPE_RE, _CTX_TEMPLATE, "template"),
        (_HTTP_SPLIT_CRLF_RE, _CTX_HTTP_SPLIT, "http_split"),
        (
            _path_only_pattern(r"\.env(?:\.\w+)?"),
            _CTX_SENSITIVE_FILE,
            "sensitive_file",
        ),
        (
            _path_only_pattern(
                r"(?:(?!config)[\w-])*config[\w-]*\.(?:env|yml|yaml|json|toml|ini|xml|conf)"
            ),
            _CTX_SENSITIVE_FILE,
            "sensitive_file",
        ),
        (
            _path_only_pattern(rf"{_PATH_ONLY_CHAR_RE}*\.map"),
            _CTX_SENSITIVE_FILE,
            "sensitive_file",
        ),
        (
            _path_only_pattern(
                rf"{_PATH_ONLY_CHAR_RE}*\.(?:ts|tsx|jsx|py|rb|java|go|rs|php|pl|sh|sql)"
            ),
            _CTX_SENSITIVE_FILE,
            "sensitive_file",
        ),
        (
            _path_only_pattern(r"\.(?:git|svn|hg|bzr)"),
            _CTX_SENSITIVE_FILE,
            "sensitive_file",
        ),
        (
            _PATH_ONLY_PREFIX_RE + rf"{_PATH_ONLY_CHAR_RE}*\.\w+~(?:\?\S*)?\s*\Z",
            _CTX_SENSITIVE_FILE,
            "sensitive_file",
        ),
        (
            _path_only_pattern(
                r"(?:wp-(?:admin|login|content|includes|config)|administrator|xmlrpc)"
                r"\.?(?:php)?"
            ),
            _CTX_CMS_PROBING,
            "cms_probing",
        ),
        (
            _path_only_pattern(r"(?:phpinfo|info|test|php_info)\.php"),
            _CTX_CMS_PROBING,
            "cms_probing",
        ),
        (
            _path_only_pattern(
                rf"{_PATH_ONLY_CHAR_RE}*\.(?:bak|backup|old|orig|save|swp|swo|tmp|temp)"
            ),
            _CTX_CMS_PROBING,
            "cms_probing",
        ),
        (
            _path_only_pattern(
                r"(?:\.htaccess|\.htpasswd|\.DS_Store|Thumbs\.db"
                r"|\.npmrc|\.dockerenv|web\.config)"
            ),
            _CTX_CMS_PROBING,
            "cms_probing",
        ),
        (
            _path_only_pattern(
                rf"{_PATH_ONLY_CHAR_RE}*\.(?:asp|aspx|jsp|jsa|jhtml|shtml|cfm|cgi|do"
                r"|action|lua|inc|woa|nsf|esp)"
            ),
            _CTX_RECON,
            "recon",
        ),
        (
            _nested_path_pattern(
                rf"(?:management|config_dump|credentials|system{_PATH_ONLY_SEP_RE}version"
                rf"|version{_PATH_ONLY_SEP_RE}system)"
            ),
            _CTX_RECON,
            "recon",
        ),
        (
            rf"\A{_PATH_ONLY_SEP_RE}(?:system|version)" + _PATH_ONLY_SUFFIX_RE,
            _CTX_RECON,
            "recon",
        ),
        (
            _path_only_pattern(r"(?:actuator|server-status|telescope)"),
            _CTX_RECON,
            "recon",
        ),
        (
            r"(?:CSCOE|dana-(?:na|cached)|sslvpn|RDWeb|/owa/|/ecp/"
            r"|global-protect|ssl-vpn/|svpn/|sonicui|/remote/login"
            r"|myvpn|vpntunnel|versa/login)",
            _CTX_RECON,
            "recon",
        ),
        (
            _path_only_pattern(
                r"(?:geoserver|confluence|nifi|ScadaBR|pandora_console"
                r"|centreon|kylin|decisioncenter|evox|MagicInfo|metasys"
                r"|officescan|helpdesk|ignite)",
                trailing=rf"(?:[.\-]{_PATH_ONLY_CHAR_RE}*)?",
            ),
            _CTX_RECON,
            "recon",
        ),
        (
            _path_only_pattern(r"cgi-(?:bin|mod)"),
            _CTX_RECON,
            "recon",
        ),
        (
            _path_only_pattern(r"(?:HNAP1|IPCamDesc\.xml|SDK/webLanguage)"),
            _CTX_RECON,
            "recon",
        ),
        (
            _path_only_pattern(r"(?:language|languages)"),
            _CTX_RECON,
            "recon",
        ),
        (
            _path_only_pattern(
                r"(?:readme\.txt|README\.md|CHANGELOG|pom\.xml"
                r"|build\.gradle|appsettings\.json|crossdomain\.xml)",
                trailing=rf"(?:\.{_PATH_ONLY_CHAR_RE}*)?",
            ),
            _CTX_RECON,
            "recon",
        ),
        (
            _path_only_pattern(
                r"(?:sap|ise|nidp|cslu|rustfs|developmentserver"
                r"|fog/management|lms/db|json/login_session|sms_mp"
                r"|plugin/webs_model|wsman|am_bin)"
            ),
            _CTX_RECON,
            "recon",
        ),
        (r"(?:nmaplowercheck|nice\s+ports|Trinity\.txt)", _CTX_RECON, "recon"),
        (
            _path_only_pattern(r"\.(?:openclaw|clawdbot)"),
            _CTX_RECON,
            "recon",
        ),
        (
            _TOP_LEVEL_PATH_PREFIX_RE
            + r"(?:default|inicio|indice|localstart)"
            + rf"(?:\.{_PATH_ONLY_CHAR_RE}*)?"
            + _TERMINAL_PATH_SUFFIX_RE,
            _CTX_RECON,
            "recon",
        ),
        (
            _path_only_pattern(r"inicio\.html?"),
            _CTX_RECON,
            "recon",
        ),
        (
            _path_only_pattern(
                r"(?:\.streamlit|\.gpt-pilot|\.aider|\.cursor"
                r"|\.windsurf|\.copilot|\.devcontainer)"
            ),
            _CTX_RECON,
            "recon",
        ),
        (
            _path_only_pattern(
                r"(?:docker-compose|Dockerfile|Makefile|Vagrantfile"
                r"|Jenkinsfile|Procfile)(?:\.ya?ml)?"
            ),
            _CTX_RECON,
            "recon",
        ),
        (
            _path_only_pattern(
                rf"{_PATH_ONLY_CHAR_RE}*(?:secrets?|credentials?)"
                r"\.(?:py|json|yml|yaml|toml|txt|env|xml|conf|cfg)"
            ),
            _CTX_RECON,
            "recon",
        ),
        (
            _path_only_pattern(r"autodiscover"),
            _CTX_RECON,
            "recon",
        ),
        (
            _path_only_pattern(r"dns-query"),
            _CTX_RECON,
            "recon",
        ),
        (
            _path_only_pattern(r"\.git/(?:refs|index|HEAD|objects|logs)"),
            _CTX_RECON,
            "recon",
        ),
        (
            r"(?:__proto__|constructor)\s*(?:\[\s*[\"']prototype[\"']\s*\]|\.\s*prototype)|[\"']__proto__[\"']\s*:",
            _CTX_PROTO_POLLUTION,
            "proto_pollution",
        ),
        (
            r"__proto__\s*(?:\[|\.)|\[\s*[\"']?__proto__[\"']?\s*\]|"
            r"constructor\s*\[\s*[\"']?prototype[\"']?\s*\]|"
            r"\[\s*[\"']?constructor[\"']?\s*\]\s*\[\s*[\"']?prototype[\"']?\s*\]",
            _CTX_PROTO_POLLUTION,
            "proto_pollution",
        ),
        (
            _PROTO_POLLUTION_PROTOTYPE_ASSIGN_RE,
            _CTX_PROTO_POLLUTION,
            "proto_pollution",
        ),
        (
            _PROTO_POLLUTION_SET_PROTOTYPE_OF_RE,
            _CTX_PROTO_POLLUTION,
            "proto_pollution",
        ),
        (
            r"System\.Diagnostics\.Process\.Start\s*\(|System\.Reflection\.|Assembly\.Load\s*\(",
            _CTX_CODE_INJECTION,
            "code_injection",
        ),
        (
            _PY_GETATTR_INDIRECTION_RE,
            _CTX_CODE_INJECTION,
            "code_injection",
        ),
        (
            _PY_VARS_INDIRECTION_RE,
            _CTX_CODE_INJECTION,
            "code_injection",
        ),
        (_DESERIALIZATION_JAVA_B64_RE, _CTX_DESERIALIZATION, "deserialization"),
        (_DESERIALIZATION_DOTNET_B64_RE, _CTX_DESERIALIZATION, "deserialization"),
        (_DESERIALIZATION_PICKLE_B64_RE, _CTX_DESERIALIZATION, "deserialization"),
        (_DESERIALIZATION_RUBY_B64_RE, _CTX_DESERIALIZATION, "deserialization"),
        (
            _DESERIALIZATION_PICKLE_OS_GLOBAL_RE,
            _CTX_DESERIALIZATION,
            "deserialization",
        ),
        (r"c__builtin__", _CTX_DESERIALIZATION, "deserialization"),
        (r"csubprocess", _CTX_DESERIALIZATION, "deserialization"),
        (r"cposix", _CTX_DESERIALIZATION, "deserialization"),
        (
            _DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE,
            _CTX_DESERIALIZATION,
            "deserialization",
        ),
        (r'O:\d+:"', _CTX_DESERIALIZATION, "deserialization"),
        (r'C:\d+:"', _CTX_DESERIALIZATION, "deserialization"),
        (r'E:\d+:"', _CTX_DESERIALIZATION, "deserialization"),
        (r"<ObjectDataProvider\b", _CTX_DESERIALIZATION, "deserialization"),
    ]

    patterns: list[str] = [p[0] for p in _pattern_definitions]

    custom_patterns: set[str]
    compiled_patterns: list[tuple[re.Pattern, frozenset[str], str]]
    compiled_custom_patterns: set[tuple[re.Pattern, frozenset[str], str]]
    redis_handler: Any
    agent_handler: Any
    _detection_state: _DetectionState

    def __new__(
        cls: type["SusPatternsManager"], config: Any = None
    ) -> "SusPatternsManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.custom_patterns = set()
            cls._instance.compiled_patterns = [
                (re.compile(pattern, re.IGNORECASE), contexts, category)
                for pattern, contexts, category in cls._pattern_definitions
            ]
            cls._instance.compiled_custom_patterns = set()
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None

            cls._config = config

            if _supports_enhanced_config(config):
                cls._instance._detection_state = _build_enhanced_detection_state(config)
            else:
                cls._instance._detection_state = _LEGACY_DETECTION_STATE

        return cls._instance

    @property
    def _compiler(self) -> PatternCompiler | None:
        return self._detection_state.compiler

    @_compiler.setter
    def _compiler(self, value: PatternCompiler | None) -> None:
        self._detection_state = self._detection_state._replace(compiler=value)

    @property
    def _preprocessor(self) -> ContentPreprocessor | None:
        return self._detection_state.preprocessor

    @_preprocessor.setter
    def _preprocessor(self, value: ContentPreprocessor | None) -> None:
        self._detection_state = self._detection_state._replace(preprocessor=value)

    @property
    def _semantic_analyzer(self) -> SemanticAnalyzer | None:
        return self._detection_state.semantic_analyzer

    @_semantic_analyzer.setter
    def _semantic_analyzer(self, value: SemanticAnalyzer | None) -> None:
        self._detection_state = self._detection_state._replace(semantic_analyzer=value)

    @property
    def _performance_monitor(self) -> PerformanceMonitor | None:
        return self._detection_state.performance_monitor

    @_performance_monitor.setter
    def _performance_monitor(self, value: PerformanceMonitor | None) -> None:
        self._detection_state = self._detection_state._replace(
            performance_monitor=value
        )

    @property
    def _semantic_threshold(self) -> float:
        return self._detection_state.semantic_threshold

    @_semantic_threshold.setter
    def _semantic_threshold(self, value: float) -> None:
        self._detection_state = self._detection_state._replace(semantic_threshold=value)

    @property
    def _threat_score_threshold(self) -> float:
        return self._detection_state.threat_score_threshold

    @_threat_score_threshold.setter
    def _threat_score_threshold(self, value: float) -> None:
        self._detection_state = self._detection_state._replace(
            threat_score_threshold=value
        )

    def configure(self, config: Any) -> None:
        if not _supports_enhanced_config(config):
            return
        SusPatternsManager._config = config
        self._detection_state = _build_enhanced_detection_state(config)

    def _resolve_state(self, state: _DetectionState | None) -> _DetectionState:
        return state if state is not None else self._detection_state

    async def initialize_redis(self, redis_handler: Any) -> None:
        self.redis_handler = redis_handler
        if self.redis_handler:
            cached_patterns = await self.redis_handler.get_key("patterns", "custom")
            if cached_patterns:
                patterns = cached_patterns.split(",")
                for pattern in patterns:
                    if pattern not in self.custom_patterns:
                        restored = await self.add_pattern(pattern, custom=True)
                        if not restored:
                            logger.warning(
                                f"Skipped restoring persisted pattern: "
                                f"{pattern[:50]}..."
                            )

    async def initialize_agent(self, agent_handler: Any) -> None:
        self.agent_handler = agent_handler

    async def _send_pattern_event(
        self,
        event_type: str,
        ip_address: str,
        action_taken: str,
        reason: str,
        **kwargs: Any,
    ) -> None:
        if not self.agent_handler:
            return

        try:
            from guard_core._pydantic_plugin_mute import get_telemetry_model

            SecurityEvent = get_telemetry_model("SecurityEvent")

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=event_type,
                ip_address=ip_address,
                action_taken=action_taken,
                reason=reason,
                metadata=kwargs,
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            logger.error(f"Failed to send pattern event to agent: {e}")

    async def _preprocess_content(
        self,
        content: str,
        correlation_id: str | None,
        *,
        state: _DetectionState | None = None,
    ) -> tuple[str, bool]:
        state = self._resolve_state(state)
        preprocessor = state.preprocessor
        if not preprocessor:
            max_length = getattr(
                self._config, "detection_max_content_length", _DEFAULT_MAX_SCAN_LENGTH
            )
            return content[:max_length], False

        context_preprocessor = ContentPreprocessor(
            max_content_length=preprocessor.max_content_length,
            preserve_attack_patterns=preprocessor.preserve_attack_patterns,
            agent_handler=self.agent_handler,
            correlation_id=correlation_id,
            max_full_scan_bytes=preprocessor._MAX_FULL_SCAN_BYTES,
        )
        decode_budget_exhausted = [False]
        processed = await context_preprocessor.preprocess(
            content, decode_budget_exhausted
        )
        return processed, decode_budget_exhausted[0]

    async def _check_regex_pattern(
        self,
        pattern: re.Pattern,
        content: str,
        ip_address: str,
        pattern_start: float,
        category: str,
        *,
        state: _DetectionState | None = None,
        context: str = "unknown",
    ) -> tuple[dict | None, bool]:
        state = self._resolve_state(state)
        windowed_finder = _WINDOWED_PATTERN_FINDERS.get(pattern.pattern)
        if windowed_finder is not None:
            return await self._check_windowed_pattern(
                pattern, windowed_finder, content, pattern_start, category, context
            )

        timeout_occurred = False

        scan_window_bounds = _SCAN_WINDOW_PATTERNS.get(pattern.pattern)
        if scan_window_bounds is not None:
            scan_window_matches = _iter_scan_window_matches(
                content, pattern, scan_window_bounds
            )
            threat = _first_accepted_regex_threat(
                scan_window_matches, pattern, category, pattern_start, context
            )
            return threat, timeout_occurred

        compiler = state.compiler

        if compiler:
            scan_window_matcher = _PATTERN_SCAN_WINDOW_MATCHERS.get(pattern.pattern)
            if scan_window_matcher is not None:
                matches = scan_window_matcher(content, pattern)
            else:
                safe_finder = compiler.create_async_safe_finditer_matcher(
                    pattern, inline_safe=category != "custom"
                )
                matches = await safe_finder(content)
            timeout_threshold = 0.9 * compiler.default_timeout
            if not matches and time.monotonic() - pattern_start >= timeout_threshold:
                timeout_occurred = True
                logger.warning(f"Pattern timeout: {pattern.pattern[:50]}...")

            threat = _first_accepted_regex_threat(
                iter(matches), pattern, category, pattern_start, context
            )
            if threat:
                return threat, timeout_occurred
        else:
            threat, timeout_occurred = await self._check_regex_pattern_with_retry(
                pattern, content, ip_address, pattern_start, category, context
            )
            if threat:
                return threat, timeout_occurred

        return None, timeout_occurred

    async def _check_windowed_pattern(
        self,
        pattern: re.Pattern,
        finder: Callable[[str], Iterator[re.Match]],
        content: str,
        pattern_start: float,
        category: str,
        context: str,
    ) -> tuple[dict | None, bool]:
        timeout = getattr(
            self._config, "detection_compiler_timeout", _DEFAULT_COMPILER_TIMEOUT
        )
        future = shared_regex_executor().submit(lambda: list(finder(content)))
        try:
            matches = future.result(timeout=timeout)
            report_scan_success()
        except concurrent.futures.TimeoutError:
            logger.warning(f"Pattern timeout: {pattern.pattern[:50]}...")
            future.cancel()
            report_scan_timeout()
            return None, True
        except Exception as e:
            logger.error(
                f"Error in windowed regex search for pattern "
                f"{pattern.pattern[:50]}...: {e}"
            )
            return None, False

        threat = _first_accepted_regex_threat(
            iter(matches), pattern, category, pattern_start, context
        )
        return threat, False

    async def _check_regex_pattern_with_retry(
        self,
        pattern: re.Pattern,
        content: str,
        ip_address: str,
        pattern_start: float,
        category: str,
        context: str = "unknown",
    ) -> tuple[dict | None, bool]:
        search_from = 0
        timeout_occurred = False

        while True:
            match, occurred = await self._check_pattern_with_timeout(
                pattern, content, ip_address, pattern_start, search_from
            )
            timeout_occurred = timeout_occurred or occurred
            if match is None or occurred:
                break

            threat = _build_regex_threat(
                pattern, match, category, pattern_start, context
            )
            if threat:
                return threat, timeout_occurred

            search_from = (
                match.end() + 1 if match.end() == match.start() else match.end()
            )

        return None, timeout_occurred

    async def _check_pattern_with_timeout(
        self,
        pattern: re.Pattern,
        content: str,
        ip_address: str,
        pattern_start: float,
        search_from: int = 0,
    ) -> tuple[re.Match | None, bool]:
        timeout = getattr(
            self._config, "detection_compiler_timeout", _DEFAULT_COMPILER_TIMEOUT
        )
        future = shared_regex_executor().submit(pattern.search, content, search_from)
        try:
            match = future.result(timeout=timeout)
            report_scan_success()
            return match, False
        except concurrent.futures.TimeoutError:
            logger.warning(
                f"Regex timeout exceeded for pattern: "
                f"{pattern.pattern[:50]}... "
                f"Potential ReDoS attack blocked. IP: {ip_address}"
            )
            future.cancel()
            report_scan_timeout()
            return None, True
        except Exception as e:
            logger.error(
                f"Error in regex search for pattern {pattern.pattern[:50]}...: {e}"
            )
            return None, False

    _KNOWN_CONTEXTS = frozenset(
        {"query_param", "header", "url_path", "request_body", "unknown"}
    )

    @staticmethod
    def _normalize_context(context: str | None) -> str:
        if context is None:
            return "unknown"
        normalized = context.split(":", 1)[0]
        if normalized not in SusPatternsManager._KNOWN_CONTEXTS:
            return "unknown"
        return normalized

    async def _check_regex_patterns(
        self,
        content: str,
        ip_address: str,
        correlation_id: str | None,
        context: str = "unknown",
        enabled_categories: set[str] | None = None,
        *,
        state: _DetectionState | None = None,
        raw_view_only: bool | None = None,
        url_decoded_view_only: bool | None = None,
    ) -> tuple[list[dict], list[str], list[str]]:
        state = self._resolve_state(state)
        threats = []
        matched_patterns = []
        timeouts = []

        all_patterns = await self.get_all_compiled_patterns()
        normalized = self._normalize_context(context)
        skip_filter = normalized in ("unknown", "request_body")
        performance_monitor = state.performance_monitor

        for pattern, contexts, category in all_patterns:
            if _pattern_should_be_skipped(
                pattern,
                contexts,
                category,
                raw_view_only=raw_view_only,
                skip_filter=skip_filter,
                normalized_context=normalized,
                enabled_categories=enabled_categories,
                url_decoded_view_only=url_decoded_view_only,
            ):
                continue

            pattern_start = time.monotonic()

            scan_content = (
                _file_upload_scan_window(content)
                if category == "file_upload"
                else content
            )
            threat, timeout_occurred = await self._check_regex_pattern(
                pattern,
                scan_content,
                ip_address,
                pattern_start,
                category,
                state=state,
                context=normalized,
            )

            if timeout_occurred:
                timeouts.append(pattern.pattern)
                if not threat:
                    threat = _build_timeout_threat(pattern, category, pattern_start)

            if threat:
                threats.append(threat)
                matched_patterns.append(pattern.pattern)

            if performance_monitor:
                await performance_monitor.record_metric(
                    pattern=pattern.pattern,
                    execution_time=time.monotonic() - pattern_start,
                    content_length=len(content),
                    matched=bool(threat),
                    timeout=timeout_occurred,
                    agent_handler=self.agent_handler,
                    correlation_id=correlation_id,
                )

        return threats, matched_patterns, timeouts

    async def _check_semantic_threats(
        self,
        content: str,
        *,
        state: _DetectionState | None = None,
        raw_content: str | None = None,
    ) -> tuple[list[dict], float]:
        state = self._resolve_state(state)
        semantic_analyzer = state.semantic_analyzer
        if not semantic_analyzer:
            return [], 0.0

        if looks_like_binary_content(
            raw_content if raw_content is not None else content
        ):
            return [], 0.0

        semantic_threshold = state.semantic_threshold
        semantic_budget = (
            state.preprocessor.max_content_length
            if state.preprocessor
            else len(content)
        )
        semantic_analysis = semantic_analyzer.analyze(content[:semantic_budget])
        semantic_score = semantic_analyzer.get_threat_score(semantic_analysis)
        threats = []

        if semantic_score > semantic_threshold:
            attack_probs = semantic_analysis.get("attack_probabilities", {})

            for attack_type, probability in attack_probs.items():
                if probability >= semantic_threshold:
                    threats.append(
                        {
                            "type": "semantic",
                            "attack_type": attack_type,
                            "probability": probability,
                            "analysis": semantic_analysis,
                        }
                    )

            if not threats and semantic_score >= semantic_threshold:
                threats.append(
                    {
                        "type": "semantic",
                        "attack_type": "suspicious",
                        "threat_score": semantic_score,
                        "analysis": semantic_analysis,
                    }
                )

        return threats, semantic_score

    async def _calculate_threat_score(
        self, regex_threats: list, semantic_threats: list
    ) -> float:
        if not (regex_threats or semantic_threats):
            return 0.0

        anomaly = _regex_anomaly(regex_threats)
        semantic_scores = [
            t.get("probability", t.get("threat_score", 0.0)) for t in semantic_threats
        ]
        semantic_max = max(semantic_scores) if semantic_scores else 0.0
        return min(max(anomaly, semantic_max), 1.0)

    async def _check_raw_view_patterns(
        self,
        content: str,
        ip_address: str,
        context: str,
        correlation_id: str | None,
        enabled_categories: set[str] | None,
        state: _DetectionState,
    ) -> tuple[list[dict], list[str], list[str]]:
        preprocessor = state.preprocessor
        if not preprocessor:
            return [], [], []

        raw_view_content = preprocessor.preprocess_signal_preserving(content)
        return await self._check_regex_patterns(
            raw_view_content,
            ip_address,
            correlation_id,
            context,
            enabled_categories,
            state=state,
            raw_view_only=True,
        )

    async def _check_decoded_view_path_traversal(
        self,
        processed_content: str,
        content: str,
        context: str,
        enabled_categories: set[str] | None,
        state: _DetectionState,
    ) -> dict[str, Any] | None:
        preprocessor = state.preprocessor
        if not preprocessor:
            return None
        if self._normalize_context(context) not in _CTX_PATH_TRAVERSAL:
            return None
        if (
            enabled_categories is not None
            and "path_traversal" not in enabled_categories
        ):
            return None

        pattern_start = time.monotonic()
        raw_view_content = preprocessor.preprocess_signal_preserving(content)
        decoded_matches = list(
            _PATH_TRAVERSAL_DECODED_SHAPE_RE.finditer(processed_content)
        )
        raw_count = len(_PATH_TRAVERSAL_DECODED_SHAPE_RE.findall(raw_view_content))
        if len(decoded_matches) <= raw_count:
            return None

        match = decoded_matches[0]
        return {
            "type": "regex",
            "pattern": _PATH_TRAVERSAL_DECODED_SHAPE_RE.pattern,
            "match": _sanitize_for_reporting(match.group()),
            "position": match.start(),
            "execution_time": time.monotonic() - pattern_start,
            "category": "path_traversal",
            "weight": _resolve_pattern_weight(
                _PATH_TRAVERSAL_DECODED_SHAPE_RE.pattern, "path_traversal"
            ),
        }

    async def _check_url_decoded_view_patterns(
        self,
        content: str,
        ip_address: str,
        context: str,
        correlation_id: str | None,
        enabled_categories: set[str] | None,
        state: _DetectionState,
    ) -> tuple[list[dict], list[str], list[str], bool]:
        preprocessor = state.preprocessor
        if not preprocessor:
            return [], [], [], False

        decode_budget_exhausted: list[bool] = [False]
        url_decoded_view_content = (
            await preprocessor.preprocess_url_decoded_newline_preserving(
                content, decode_budget_exhausted
            )
        )
        threats, matched, timeouts = await self._check_regex_patterns(
            url_decoded_view_content,
            ip_address,
            correlation_id,
            context,
            enabled_categories,
            state=state,
            url_decoded_view_only=True,
        )
        return threats, matched, timeouts, decode_budget_exhausted[0]

    async def _check_short_base64_additive_view_patterns(
        self,
        content: str,
        ip_address: str,
        context: str,
        correlation_id: str | None,
        enabled_categories: set[str] | None,
        state: _DetectionState,
    ) -> tuple[list[dict], list[str], list[str]]:
        preprocessor = state.preprocessor
        if not preprocessor:
            return [], [], []
        if self._normalize_context(context) not in ("request_body", "query_param"):
            return [], [], []

        additive_view_content = preprocessor.preprocess_short_base64_additive_view(
            content
        )
        if not additive_view_content:
            return [], [], []

        return await self._check_regex_patterns(
            additive_view_content,
            ip_address,
            correlation_id,
            context,
            enabled_categories,
            state=state,
        )

    async def detect(
        self,
        content: str,
        ip_address: str,
        context: str = "unknown",
        correlation_id: str | None = None,
        enabled_categories: set[str] | None = None,
    ) -> dict[str, Any]:
        original_content = content
        execution_start = time.monotonic()
        state = self._detection_state

        processed_content, decode_budget_exhausted = await self._preprocess_content(
            content, correlation_id, state=state
        )

        regex_threats, matched_patterns, timeouts = await self._check_regex_patterns(
            processed_content,
            ip_address,
            correlation_id,
            context,
            enabled_categories,
            state=state,
            raw_view_only=False if state.preprocessor else None,
        )

        raw_threats, raw_matched, raw_timeouts = await self._check_raw_view_patterns(
            content, ip_address, context, correlation_id, enabled_categories, state
        )
        regex_threats = regex_threats + raw_threats
        matched_patterns = matched_patterns + raw_matched
        timeouts = timeouts + raw_timeouts

        decoded_view_threat = await self._check_decoded_view_path_traversal(
            processed_content, content, context, enabled_categories, state
        )
        if decoded_view_threat:
            regex_threats = regex_threats + [decoded_view_threat]
            matched_patterns = matched_patterns + [decoded_view_threat["pattern"]]

        (
            url_decoded_threats,
            url_decoded_matched,
            url_decoded_timeouts,
            url_decoded_budget_exhausted,
        ) = await self._check_url_decoded_view_patterns(
            content, ip_address, context, correlation_id, enabled_categories, state
        )
        regex_threats = regex_threats + url_decoded_threats
        matched_patterns = matched_patterns + url_decoded_matched
        timeouts = timeouts + url_decoded_timeouts

        if decode_budget_exhausted or url_decoded_budget_exhausted:
            exhaustion_threat = _decode_budget_exhausted_threat()
            regex_threats = regex_threats + [exhaustion_threat]
            matched_patterns = matched_patterns + [exhaustion_threat["pattern"]]

        (
            short_base64_threats,
            short_base64_matched,
            short_base64_timeouts,
        ) = await self._check_short_base64_additive_view_patterns(
            content, ip_address, context, correlation_id, enabled_categories, state
        )
        regex_threats = regex_threats + short_base64_threats
        matched_patterns = matched_patterns + short_base64_matched
        timeouts = timeouts + short_base64_timeouts

        semantic_threats, semantic_score = await self._check_semantic_threats(
            processed_content, state=state, raw_content=original_content
        )

        threats = regex_threats + semantic_threats
        is_threat = (
            _regex_anomaly(regex_threats) >= state.threat_score_threshold
            or len(semantic_threats) > 0
        )

        threat_score = await self._calculate_threat_score(
            regex_threats, semantic_threats
        )

        total_execution_time = time.monotonic() - execution_start

        if state.performance_monitor:
            await state.performance_monitor.record_metric(
                pattern="overall_detection",
                execution_time=total_execution_time,
                content_length=len(content),
                matched=is_threat,
                timeout=False,
                agent_handler=self.agent_handler,
                correlation_id=correlation_id,
            )

        detection_method = "enhanced" if state.compiler else "legacy"

        if is_threat:
            await self._send_threat_event(
                matched_patterns,
                semantic_threats,
                ip_address,
                context,
                content,
                threat_score,
                threats,
                regex_threats,
                timeouts,
                total_execution_time,
                correlation_id,
                detection_method,
            )

        return {
            "is_threat": is_threat,
            "threat_score": threat_score,
            "threats": threats,
            "context": context,
            "original_length": len(original_content),
            "processed_length": len(processed_content),
            "execution_time": total_execution_time,
            "detection_method": detection_method,
            "timeouts": timeouts,
            "correlation_id": correlation_id,
        }

    async def _send_threat_event(
        self,
        matched_patterns: list,
        semantic_threats: list,
        ip_address: str,
        context: str,
        content: str,
        threat_score: float,
        threats: list,
        regex_threats: list,
        timeouts: list,
        execution_time: float,
        correlation_id: str | None,
        detection_method: str | None = None,
    ) -> None:
        from guard_core.core.events.event_types import EVENT_PATTERN_DETECTED

        if detection_method is None:
            detection_method = "enhanced" if self._compiler else "legacy"

        pattern_info = "unknown"
        if matched_patterns:
            pattern_info = matched_patterns[0]
        elif semantic_threats:
            pattern_info = f"semantic:{semantic_threats[0]['attack_type']}"

        await self._send_pattern_event(
            event_type=EVENT_PATTERN_DETECTED,
            ip_address=ip_address,
            action_taken="threat_detected",
            reason=f"Threat detected in {context}",
            pattern=pattern_info,
            context=context,
            content_preview=_sanitize_for_reporting(
                content[:100] if len(content) > 100 else content
            ),
            threat_score=threat_score,
            threats=len(threats),
            regex_threats=len(regex_threats),
            semantic_threats=len(semantic_threats),
            timeouts=len(timeouts),
            detection_method=detection_method,
            execution_time_ms=int(execution_time * 1000),
            correlation_id=correlation_id,
        )

    async def detect_pattern_match(
        self,
        content: str,
        ip_address: str,
        context: str = "unknown",
        correlation_id: str | None = None,
    ) -> tuple[bool, str | None]:
        result = await self.detect(content, ip_address, context, correlation_id)

        if result["is_threat"]:
            if result["threats"]:
                threat = result["threats"][0]
                if threat["type"] == "regex":
                    return True, threat["pattern"]
                elif threat["type"] == "semantic":
                    return True, f"semantic:{threat.get('attack_type', 'suspicious')}"
            return True, "unknown"

        return False, None

    @classmethod
    async def add_pattern(cls, pattern: str, custom: bool = False) -> bool:
        instance = cls()

        compiler = instance._compiler or PatternCompiler()
        max_content_length = getattr(
            instance._config,
            "detection_max_body_inspect_bytes",
            _DEFAULT_MAX_BODY_INSPECT_BYTES,
        )
        validate_with_cap = functools.partial(
            compiler.validate_pattern_safety, max_content_length=max_content_length
        )
        is_safe, reason = await asyncio.to_thread(validate_with_cap, pattern)
        if not is_safe:
            logger.warning(f"Rejected unsafe pattern ({reason}): {pattern[:50]}...")
            return False

        compiled_pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        compiled_tuple = (compiled_pattern, _CTX_ALL, "custom")
        if custom:
            instance.compiled_custom_patterns.add(compiled_tuple)
            instance.custom_patterns.add(pattern)

            if instance.redis_handler:
                await instance.redis_handler.set_key(
                    "patterns", "custom", ",".join(instance.custom_patterns)
                )
        else:
            instance.compiled_patterns.append(compiled_tuple)
            instance.patterns.append(pattern)

        if instance._compiler:
            await instance._compiler.clear_cache()

        if instance.agent_handler:
            details = f"{'Custom' if custom else 'Default'} pattern added"
            await instance._send_pattern_event(
                event_type="pattern_added",
                ip_address="system",
                action_taken="pattern_added",
                reason=f"{details} to detection system",
                pattern=pattern,
                pattern_type="custom" if custom else "default",
                total_patterns=len(instance.custom_patterns)
                if custom
                else len(instance.patterns),
            )

        return True

    async def _remove_custom_pattern(self, pattern: str) -> bool:
        if pattern not in self.custom_patterns:
            return False

        self.custom_patterns.discard(pattern)

        self.compiled_custom_patterns = {
            (p, ctx, cat)
            for p, ctx, cat in self.compiled_custom_patterns
            if p.pattern != pattern
        }

        if self.redis_handler:
            await self.redis_handler.set_key(
                "patterns", "custom", ",".join(self.custom_patterns)
            )

        return True

    async def _remove_default_pattern(self, pattern: str) -> bool:
        if pattern not in self.patterns:
            return False

        index = self.patterns.index(pattern)
        self.patterns.pop(index)

        if 0 <= index < len(self.compiled_patterns):
            self.compiled_patterns.pop(index)
            return True

        return False

    async def _clear_pattern_caches(self, pattern: str) -> None:
        if self._compiler:
            await self._compiler.clear_cache()
        if self._performance_monitor:
            await self._performance_monitor.remove_pattern_stats(pattern)

    async def _send_pattern_removal_event(
        self, pattern: str, custom: bool, total_patterns: int
    ) -> None:
        if not self.agent_handler:
            return

        details = f"{'Custom' if custom else 'Default'} pattern removed"
        await self._send_pattern_event(
            event_type="pattern_removed",
            ip_address="system",
            action_taken="pattern_removed",
            reason=f"{details} from detection system",
            pattern=pattern,
            pattern_type="custom" if custom else "default",
            total_patterns=total_patterns,
        )

    @classmethod
    async def remove_pattern(cls, pattern: str, custom: bool = False) -> bool:
        instance = cls()

        if custom:
            pattern_removed = await instance._remove_custom_pattern(pattern)
        else:
            pattern_removed = await instance._remove_default_pattern(pattern)

        if pattern_removed:
            await instance._clear_pattern_caches(pattern)

        if pattern_removed:
            total_patterns = (
                len(instance.custom_patterns) if custom else len(instance.patterns)
            )
            await instance._send_pattern_removal_event(pattern, custom, total_patterns)

        return pattern_removed

    @classmethod
    async def get_default_patterns(cls) -> list[str]:
        instance = cls()
        return instance.patterns.copy()

    @classmethod
    async def get_custom_patterns(cls) -> list[str]:
        instance = cls()
        return list(instance.custom_patterns)

    @classmethod
    async def get_all_patterns(cls) -> list[str]:
        instance = cls()
        return instance.patterns + list(instance.custom_patterns)

    @classmethod
    async def get_default_compiled_patterns(
        cls,
    ) -> list[tuple[re.Pattern, frozenset[str], str]]:
        instance = cls()
        return instance.compiled_patterns.copy()

    @classmethod
    async def get_custom_compiled_patterns(
        cls,
    ) -> list[tuple[re.Pattern, frozenset[str], str]]:
        instance = cls()
        return list(instance.compiled_custom_patterns)

    @classmethod
    async def get_all_compiled_patterns(
        cls,
    ) -> list[tuple[re.Pattern, frozenset[str], str]]:
        instance = cls()
        return instance.compiled_patterns + list(instance.compiled_custom_patterns)

    @classmethod
    async def get_performance_stats(cls) -> dict[str, Any] | None:
        instance = cls()
        performance_monitor = instance._performance_monitor
        if performance_monitor:
            return {
                "summary": await performance_monitor.get_summary_stats(),
                "slow_patterns": await performance_monitor.get_slow_patterns(),
                "problematic_patterns": (
                    await performance_monitor.get_problematic_patterns()
                ),
            }
        return None

    @classmethod
    async def get_component_status(cls) -> dict[str, bool]:
        instance = cls()
        state = instance._detection_state
        return {
            "compiler": state.compiler is not None,
            "preprocessor": state.preprocessor is not None,
            "semantic_analyzer": state.semantic_analyzer is not None,
            "performance_monitor": state.performance_monitor is not None,
        }

    async def configure_semantic_threshold(self, threshold: float) -> None:
        self._semantic_threshold = max(0.0, min(1.0, threshold))

    @classmethod
    async def reset(cls) -> None:
        if cls._instance is not None:
            cls._instance.custom_patterns.clear()
            cls._instance.compiled_custom_patterns.clear()

            cls._instance.redis_handler = None
            cls._instance.agent_handler = None

            if hasattr(cls._instance, "_compiler") and cls._instance._compiler:
                await cls._instance._compiler.clear_cache()

            if (
                hasattr(cls._instance, "_performance_monitor")
                and cls._instance._performance_monitor
            ):
                await cls._instance._performance_monitor.clear_stats()

            cls._config = None


sus_patterns_handler = SusPatternsManager()
