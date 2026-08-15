import asyncio
import concurrent.futures
import ipaddress
import logging
import re
import time
from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Any, NamedTuple

from guard_core.detection_engine import (
    ContentPreprocessor,
    PatternCompiler,
    PerformanceMonitor,
    SemanticAnalyzer,
)
from guard_core.detection_engine.compiler import (
    report_scan_success,
    report_scan_timeout,
    shared_regex_executor,
)

logger = logging.getLogger("guard_core.handlers.suspatterns")

_DEFAULT_MAX_SCAN_LENGTH = 10000
_DEFAULT_COMPILER_TIMEOUT = 2.0

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


_CTX_XSS = frozenset({"query_param", "header", "request_body", "unknown"})
_CTX_SQLI = frozenset({"query_param", "request_body", "unknown"})
_CTX_DIR_TRAVERSAL = frozenset({"url_path", "query_param", "request_body", "unknown"})
_CTX_CMD_INJECTION = frozenset({"query_param", "request_body", "unknown"})
_CTX_FILE_INCLUSION = frozenset({"url_path", "query_param", "request_body", "unknown"})
_CTX_LDAP = frozenset({"query_param", "request_body", "unknown"})
_CTX_XML = frozenset({"header", "request_body", "unknown"})
_CTX_SSRF = frozenset({"query_param", "request_body", "unknown"})
_CTX_NOSQL = frozenset({"query_param", "request_body", "unknown"})
_CTX_FILE_UPLOAD = frozenset({"header", "request_body", "unknown"})
_CTX_PATH_TRAVERSAL = frozenset({"url_path", "query_param", "request_body", "unknown"})
_CTX_TEMPLATE = frozenset({"query_param", "request_body", "unknown"})
_CTX_HTTP_SPLIT = frozenset({"header", "query_param", "request_body", "unknown"})
_CTX_SENSITIVE_FILE = frozenset({"url_path", "request_body", "unknown"})
_CTX_CMS_PROBING = frozenset({"url_path", "request_body", "unknown"})
_CTX_RECON = frozenset({"url_path", "unknown"})
_CTX_PROTO_POLLUTION = frozenset({"query_param", "request_body", "unknown"})
_CTX_CODE_INJECTION = frozenset({"query_param", "request_body", "unknown"})
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
}

_SELECT_FROM_RE = r"(?i)\bSELECT\b(?:(?!\bSELECT\b)[\w\s,\*().])*?\bFROM\b"
_SELECT_STAR_RE = r"(?i)SELECT\s+\*"
_WHERE_CLAUSE_RE = r'(?i)\bWHERE\s+[\w."]+\s*(?:=|<|>|<=|>=|LIKE|IN)\b'

_PATH_ONLY_CHAR_RE = r"[\w.\-~%]"
_PATH_ONLY_SEP_RE = r"[/\\]"
_PATH_ONLY_PREFIX_RE = (
    rf"\A{_PATH_ONLY_SEP_RE}?(?:{_PATH_ONLY_CHAR_RE}+{_PATH_ONLY_SEP_RE})*"
)
_PATH_ONLY_SUFFIX_RE = rf"(?:{_PATH_ONLY_SEP_RE}{_PATH_ONLY_CHAR_RE}*)*(?:\?\S*)?\s*\Z"

_NESTED_TOP_LEVEL_PATH_PREFIX_RE = (
    rf"\A{_PATH_ONLY_SEP_RE}(?:{_PATH_ONLY_CHAR_RE}+{_PATH_ONLY_SEP_RE})*"
)

_TOP_LEVEL_PATH_PREFIX_RE = rf"\A{_PATH_ONLY_SEP_RE}?"
_TERMINAL_PATH_SUFFIX_RE = rf"(?:{_PATH_ONLY_SEP_RE})?(?:\?\S*)?\s*\Z"

_LDAP_WILDCARD_CHAIN_RE = r"\*\)\(+\s*[a-zA-Z][\w-]*\s*="
_LDAP_ATTR_BEFORE_WILDCARD_RE = re.compile(r"\(\s*[a-zA-Z][\w-]*\s*=\Z")

_SINGLE_LINE_PREFIX_RE = r"\A(?:(?!\n).)*"
_SINGLE_LINE_SUFFIX_RE = r"\s*\Z"

_LDAP_NULL_BYTE_ATTR_RE = r"[a-zA-Z][\w-]{0,63}\s*=[\d\w\s]{0,255}\*\)+%00"
_LDAP_NULL_BYTE_BARE_RE = r"\*\)\)+%00"
_HTTP_SPLIT_CRLF_RE = r"[\r\n]\s*(?:HTTP\/[0-9.]+|Location:|Set-Cookie:)"
_SQLI_ORDER_BY_TERMINATOR_RE = (
    r"(?i)\bORDER\s+BY\s+\d+\s*(?:--|#|;|\)|,|/\*|\Z)"
    r"|(?<=[=?&])ORDER\s+BY\s+\d+\s*\n"
)
_SQLI_COMMENT_TERMINATOR_RE = r"'\s*[\);]*\s*--|'[\);]*#(?:\n|\Z)"
_PATH_TRAVERSAL_ENCODED_DOT_RE = (
    r"(?:%2e%2e|%252e%252e|%uff0e%uff0e|%c0%ae%c0%ae|%e0%40%ae|%c0%ae"
    r"%e0%80%ae|%25c0%25ae)/"
)
_CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE = (
    r"\n\s*(?:/?(?:[\w.-]+/)*env\s+)?/?(?:[\w.-]+/)*"
    r"(?:bash|sh|ksh|csh|tsch|zsh|ash)\s+-c\b"
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

DETECTION_RAW_VIEW_PATTERN_SOURCES: frozenset[str] = frozenset(
    {
        _LDAP_NULL_BYTE_ATTR_RE,
        _LDAP_NULL_BYTE_BARE_RE,
        _HTTP_SPLIT_CRLF_RE,
        _SQLI_ORDER_BY_TERMINATOR_RE,
        _SQLI_COMMENT_TERMINATOR_RE,
        _PATH_TRAVERSAL_ENCODED_DOT_RE,
        _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE,
        _DIR_TRAVERSAL_ETC_SENSITIVE_RE,
        _DIR_TRAVERSAL_WINDOWS_INI_RE,
        _DIR_TRAVERSAL_PROC_ENVIRON_RE,
        _DIR_TRAVERSAL_VAR_LOG_RE,
        _SSTI_HASH_BRACE_SHAPE_RE,
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
_BACKTICK_CONTEXT_WINDOW_CHARS = 40

_IMPLAUSIBLE_SQL_IDENTIFIER_CHARS_RE = re.compile(r"[\s/.;|&$()]")
_IMPLAUSIBLE_DOLLAR_PAREN_TOKEN_CHARS_RE = re.compile(r"[/.;|&$()]")
_IMPLAUSIBLE_DOLLAR_BRACE_TOKEN_CHARS_RE = re.compile(r"[/;|&$(){}]")
_SHELL_SPECIAL_PARAMETER_NAMES = frozenset({"ifs"})
_AMBIGUOUS_BACKTICK_INJECTION_CONTEXTS = frozenset({"query_param", "url_path"})
_CTX_CMD_INJECTION_WITH_URL_PATH = frozenset(
    {"query_param", "url_path", "request_body", "unknown"}
)
_CTX_LOG4SHELL = frozenset(
    {"query_param", "header", "request_body", "url_path", "unknown"}
)

_STRONG_SHELL_COMMAND_DENYLIST = frozenset(
    {
        "whoami",
        "uname",
        "hostname",
        "ifconfig",
        "ipconfig",
        "netstat",
        "ss",
        "ps",
        "pwd",
        "ls",
        "dir",
        "cat",
        "head",
        "tail",
        "curl",
        "wget",
        "fetch",
        "nc",
        "ncat",
        "netcat",
        "telnet",
        "bash",
        "sh",
        "ksh",
        "zsh",
        "csh",
        "ash",
        "ping",
        "dig",
        "nslookup",
        "chmod",
        "chown",
        "rm",
        "mv",
        "cp",
        "kill",
        "sudo",
        "su",
        "env",
        "export",
        "eval",
        "exec",
        "python",
        "perl",
        "ruby",
        "php",
        "node",
        "base64",
        "xxd",
        "printf",
        "id_rsa",
        "nmap",
        "socat",
        "msfconsole",
        "msfvenom",
        "certutil",
        "bitsadmin",
        "powershell",
        "pwsh",
        "mkfifo",
        "aria2c",
    }
)
_STRONG_SHELL_COMMAND_ALTERNATION = "|".join(
    re.escape(command)
    for command in sorted(_STRONG_SHELL_COMMAND_DENYLIST, key=len, reverse=True)
)
_BACKTICK_TOKEN_CHAINED_SHELL_COMMAND_RE = re.compile(
    rf"(?i)(?:;|\|\||\||&&)\s*(?:{_STRONG_SHELL_COMMAND_ALTERNATION})\b"
)
_SHELL_METACHARACTER_WINDOW_RE = re.compile(r";|\|\||\||&&|\$\(|\$\{")


def _backtick_pair_glued(content: str, start: int, end: int) -> bool:
    prefix_glued = start > 0 and bool(
        _GLUED_BACKTICK_ASCII_WORD_RE.match(content[start - 1])
    )
    suffix_glued = end < len(content) and bool(
        _GLUED_BACKTICK_ASCII_WORD_RE.match(content[end])
    )
    return prefix_glued or suffix_glued


def _backtick_pair_context_window(content: str, start: int, end: int) -> str:
    window_start = max(0, start - _BACKTICK_CONTEXT_WINDOW_CHARS)
    window_end = min(len(content), end + _BACKTICK_CONTEXT_WINDOW_CHARS)
    return content[window_start:window_end]


def _backtick_token_is_implausible_sql_identifier(token: str) -> bool:
    if _IMPLAUSIBLE_SQL_IDENTIFIER_CHARS_RE.search(token):
        return True
    return token.strip().lower() in _STRONG_SHELL_COMMAND_DENYLIST


def _strong_sql_keyword_glued_to_pair(content: str, start: int, end: int) -> bool:
    window_start = max(0, start - _BACKTICK_CONTEXT_WINDOW_CHARS)
    window_end = min(len(content), end + _BACKTICK_CONTEXT_WINDOW_CHARS)
    prefix = content[window_start:start]
    suffix = content[end:window_end]
    if _STRONG_SQL_KEYWORD_GLUED_PREFIX_RE.search(prefix):
        return True
    return bool(_STRONG_SQL_KEYWORD_GLUED_SUFFIX_RE.match(suffix))


def _glued_backtick_pair_is_injection(match: re.Match, context: str) -> bool:
    content = match.string
    start, end = match.start(), match.end()
    token = content[start + 1 : end - 1]
    if _BACKTICK_TOKEN_CHAINED_SHELL_COMMAND_RE.search(token):
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
    if stripped in _STRONG_SHELL_COMMAND_DENYLIST:
        return True
    if stripped in _SHELL_SPECIAL_PARAMETER_NAMES:
        return True
    chars_re = (
        _IMPLAUSIBLE_DOLLAR_BRACE_TOKEN_CHARS_RE
        if delimiter == "{"
        else _IMPLAUSIBLE_DOLLAR_PAREN_TOKEN_CHARS_RE
    )
    return bool(chars_re.search(token))


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


def _ldap_wildcard_chain_is_injection(match: re.Match) -> bool:
    prefix = match.string[: match.start()]
    return _LDAP_ATTR_BEFORE_WILDCARD_RE.search(prefix) is None


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


def _pattern_excluded_from_view(
    pattern: re.Pattern, raw_view_only: bool | None
) -> bool:
    is_raw_view_pattern = pattern.pattern in DETECTION_RAW_VIEW_PATTERN_SOURCES
    return (
        raw_view_only is not is_raw_view_pattern if raw_view_only is not None else False
    )


def _pattern_should_be_skipped(
    pattern: re.Pattern,
    contexts: frozenset[str],
    category: str,
    *,
    raw_view_only: bool | None,
    skip_filter: bool,
    normalized_context: str,
    enabled_categories: set[str] | None,
) -> bool:
    if _pattern_excluded_from_view(pattern, raw_view_only):
        return True
    if not skip_filter and normalized_context not in contexts:
        return True
    return (
        enabled_categories is not None
        and category != "custom"
        and category not in enabled_categories
    )


def _build_regex_threat(
    pattern: re.Pattern,
    match: re.Match,
    category: str,
    pattern_start: float,
    context: str = "unknown",
) -> dict[str, Any] | None:
    if pattern.pattern == _LEGACY_IPV4_HOST_RE and not _legacy_ipv4_match_is_blocked(
        match
    ):
        return None
    if (
        pattern.pattern == _LDAP_WILDCARD_CHAIN_RE
        and not _ldap_wildcard_chain_is_injection(match)
    ):
        return None
    if (
        pattern.pattern == _GLUED_BACKTICK_CANDIDATE_RE
        and not _glued_backtick_pair_is_injection(match, context)
    ):
        return None
    if (
        pattern.pattern == _GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE
        and not _dollar_substitution_pair_is_injection(match, context)
    ):
        return None
    return {
        "type": "regex",
        "pattern": pattern.pattern,
        "match": match.group(),
        "position": match.start(),
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


class SusPatternsManager:
    _instance = None
    _config = None

    _pattern_definitions: list[tuple[str, frozenset[str], str]] = [
        (r"<script[^>]*>[^<]*<\/script\s*>", _CTX_XSS, "xss"),
        (r"javascript:\s*[^\s]+", _CTX_XSS, "xss"),
        (
            r"(?:<[^<>]*(?<!=)(?<!=\")(?<!=')[\s/]+on\w+\s*="
            r"(?:[\"'][^\"']*[\"']|[^\s>]+))",
            _CTX_XSS,
            "xss",
        ),
        (
            r"(?:<[^<>]*\s+(?:href|src|data|action)\s*=[\s\"\']*(?:javascript|"
            r"vbscript|data):)",
            _CTX_XSS,
            "xss",
        ),
        (
            r"(?:<[^<>]*style\s*=[\s\"\']*[^<>\"\']*(?:expression|behavior|url)\s*\("
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
        (r"(?i)UNION\s+(?:ALL\s+)?SELECT", _CTX_SQLI, "sqli"),
        (
            r"(?i)('\s*(?:OR|AND)\s*[\(\s]*'?[\d\w]+\s*(?:=|LIKE|<|>|<=|>=)\s*"
            r"[\(\s]*'?[\d\w]+)",
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
        (r"(?i)(?:LOAD_FILE\s*\([^)]+\))", _CTX_SQLI, "sqli"),
        (r"(?i)(?:BENCHMARK\s*\(\s*\d+\s*,)", _CTX_SQLI, "sqli"),
        (r"(?i)(?:SLEEP\s*\(\s*\d+\s*\))", _CTX_SQLI, "sqli"),
        (
            r"(?i)(?:\/\*![0-9]*\s*(?:OR|AND|UNION|SELECT|INSERT|DELETE|DROP|"
            r"CONCAT|CHAR|UPDATE)\b)",
            _CTX_SQLI,
            "sqli",
        ),
        (r"\w/\*(?!!)[^*]*\*/\w", _CTX_SQLI, "sqli"),
        (r"(?i)(?:OR|AND)\s+'[\w\d]*'='[\w\d]*'?", _CTX_SQLI, "sqli"),
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
            r"(?:[;&|]\s*(?:\$\([^)]+\)|\$\{[^}]+\}))",
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
            r"(?:\A|;)\s*(?:/?(?:[\w.-]+/)*env\s+)?/?(?:[\w.-]+/)*"
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
            r"\b(?:eval|system|exec|shell_exec|passthru|popen|proc_open)\s*\(",
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
            r"(?:php|data|zip|rar|file|glob|expect|input|phpinfo|zlib|phar|ssh2|"
            r"rar|ogg|expect)://[^\s]+",
            _CTX_FILE_INCLUSION,
            "file_inclusion",
        ),
        (
            r"(?:(?<!:)\/\/[0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*(:[0-9]+)?(?:\/?)(?:"
            r"[a-zA-Z0-9\-\.\?,'/\\\+&amp;%\$#_]*)?)",
            _CTX_FILE_INCLUSION,
            "file_inclusion",
        ),
        (
            r"=(?:https?|ftp):\/\/[^\s'\"<>]+\/[^\s'\"<>\/]*\.(?:phtml|php[3-5]?|"
            r"phar|jsp|aspx?|cgi|pl|py|sh|txt|inc)(?![a-zA-Z0-9])",
            _CTX_FILE_INCLUSION,
            "file_inclusion",
        ),
        (r"\(\s*[|&]\s*\(\s*[^)]+=[*]", _CTX_LDAP, "ldap"),
        (r"(?:\*(?:[\s\d\w]+\s*=|=\s*[\d\w\s]+))", _CTX_LDAP, "ldap"),
        (r"(?:\(\s*[&|]\s*)", _CTX_LDAP, "ldap"),
        (_LDAP_WILDCARD_CHAIN_RE, _CTX_LDAP, "ldap"),
        (_LDAP_NULL_BYTE_ATTR_RE, _CTX_LDAP, "ldap"),
        (_LDAP_NULL_BYTE_BARE_RE, _CTX_LDAP, "ldap"),
        (r"<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>", _CTX_XML, "xml"),
        (r"(?:<!\[CDATA\[.*?\]\]>)", _CTX_XML, "xml"),
        (r"<!DOCTYPE[^>\[]*\[[\s\S]*?<!ENTITY", _CTX_XML, "xml"),
        (
            r"(?:^|\s|/)(?:(?<=://)[^\s/@]*@)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0|"
            r"\[::(?:\d*)\]|169\.254(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2}|"
            r"10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2[0-9]|3[01])(?:\.\d{1,3}){2}|"
            r"metadata\.google\.internal|metadata\.goog|100\.100\.100\.200)"
            r"(?::\d+)?(?:\s|$|/)",
            _CTX_SSRF,
            "ssrf",
        ),
        (_LEGACY_IPV4_HOST_RE, _CTX_SSRF, "ssrf"),
        (r"(?:file|dict|gopher|jar|tftp)://[^\s]+", _CTX_SSRF, "ssrf"),
        (r"://[^/\s@]*@[^/\s@]*@", _CTX_SSRF, "ssrf"),
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
            r'"\$(?:gt|gte|lt|lte|ne|eq|in|nin|all|mod)"'
            r'\s*:\s*(?:""|null|\{|\[)',
            _CTX_NOSQL,
            "nosql",
        ),
        (
            r"(?i)filename=[\"'].*?\.(?:php\d*|phar|phtml|exe|jsp|asp|aspx|sh|"
            r"bash|rb|py|pl|cgi|com|bat|cmd|vbs|vbe|js|ws|wsf|msi|hta)[\"\']",
            _CTX_FILE_UPLOAD,
            "file_upload",
        ),
        (_PATH_TRAVERSAL_ENCODED_DOT_RE, _CTX_PATH_TRAVERSAL, "path_traversal"),
        (
            r"\{\{\s*[^\}]+(?:system|exec|popen|eval|require|include)\s*\}\}",
            _CTX_TEMPLATE,
            "template",
        ),
        (
            r"\{\%\s*[^\%]+(?:system|exec|popen|eval|require|include)\s*\%\}",
            _CTX_TEMPLATE,
            "template",
        ),
        (
            r"(?i)<%[=#]?[^%]*(?:system|exec|eval|`|Runtime|IO\.|File\.|Dir\."
            r"|\d+\s*[-+*/]\s*\d+)[^%]*%>",
            _CTX_TEMPLATE,
            "template",
        ),
        (
            r"\$\{[^}]*(?:@[\w.]+@|\b\w+\s*\(|\d+\s*[*/%+\-]\s*\d+)[^}]*\}",
            _CTX_TEMPLATE,
            "template",
        ),
        (
            r"\{\{\s*[^\}]*(?:@[\w.]+@|\b\w+\s*\("
            r"|['\"]?\d+['\"]?\s*[*/%+\-]\s*['\"]?\d+['\"]?)[^\}]*\}\}",
            _CTX_TEMPLATE,
            "template",
        ),
        (_SSTI_HASH_BRACE_SHAPE_RE, _CTX_TEMPLATE, "template"),
        (_HTTP_SPLIT_CRLF_RE, _CTX_HTTP_SPLIT, "http_split"),
        (
            _PATH_ONLY_PREFIX_RE + r"\.env(?:\.\w+)?" + _PATH_ONLY_SUFFIX_RE,
            _CTX_SENSITIVE_FILE,
            "sensitive_file",
        ),
        (
            _PATH_ONLY_PREFIX_RE
            + r"[\w-]*config[\w-]*\.(?:env|yml|yaml|json|toml|ini|xml|conf)"
            + _PATH_ONLY_SUFFIX_RE,
            _CTX_SENSITIVE_FILE,
            "sensitive_file",
        ),
        (
            _PATH_ONLY_PREFIX_RE
            + rf"{_PATH_ONLY_CHAR_RE}*\.map"
            + _PATH_ONLY_SUFFIX_RE,
            _CTX_SENSITIVE_FILE,
            "sensitive_file",
        ),
        (
            _PATH_ONLY_PREFIX_RE
            + rf"{_PATH_ONLY_CHAR_RE}*\.(?:ts|tsx|jsx|py|rb|java|go|rs|php|pl|sh|sql)"
            + _PATH_ONLY_SUFFIX_RE,
            _CTX_SENSITIVE_FILE,
            "sensitive_file",
        ),
        (
            _PATH_ONLY_PREFIX_RE + r"\.(?:git|svn|hg|bzr)" + _PATH_ONLY_SUFFIX_RE,
            _CTX_SENSITIVE_FILE,
            "sensitive_file",
        ),
        (
            _PATH_ONLY_PREFIX_RE + rf"{_PATH_ONLY_CHAR_RE}*\.\w+~(?:\?\S*)?\s*\Z",
            _CTX_SENSITIVE_FILE,
            "sensitive_file",
        ),
        (
            _PATH_ONLY_PREFIX_RE
            + r"(?:wp-(?:admin|login|content|includes|config)|administrator|xmlrpc)"
            r"\.?(?:php)?" + _PATH_ONLY_SUFFIX_RE,
            _CTX_CMS_PROBING,
            "cms_probing",
        ),
        (
            _PATH_ONLY_PREFIX_RE
            + r"(?:phpinfo|info|test|php_info)\.php"
            + _PATH_ONLY_SUFFIX_RE,
            _CTX_CMS_PROBING,
            "cms_probing",
        ),
        (
            _PATH_ONLY_PREFIX_RE
            + rf"{_PATH_ONLY_CHAR_RE}*\.(?:bak|backup|old|orig|save|swp|swo|tmp|temp)"
            + _PATH_ONLY_SUFFIX_RE,
            _CTX_CMS_PROBING,
            "cms_probing",
        ),
        (
            _PATH_ONLY_PREFIX_RE + r"(?:\.htaccess|\.htpasswd|\.DS_Store|Thumbs\.db"
            r"|\.npmrc|\.dockerenv|web\.config)" + _PATH_ONLY_SUFFIX_RE,
            _CTX_CMS_PROBING,
            "cms_probing",
        ),
        (
            _PATH_ONLY_PREFIX_RE
            + rf"{_PATH_ONLY_CHAR_RE}*\.(?:asp|aspx|jsp|jsa|jhtml|shtml|cfm|cgi|do"
            r"|action|lua|inc|woa|nsf|esp)" + _PATH_ONLY_SUFFIX_RE,
            _CTX_RECON,
            "recon",
        ),
        (
            _NESTED_TOP_LEVEL_PATH_PREFIX_RE
            + rf"(?:management|config_dump|credentials|system{_PATH_ONLY_SEP_RE}version"
            rf"|version{_PATH_ONLY_SEP_RE}system)" + _PATH_ONLY_SUFFIX_RE,
            _CTX_RECON,
            "recon",
        ),
        (
            rf"\A{_PATH_ONLY_SEP_RE}(?:system|version)" + _PATH_ONLY_SUFFIX_RE,
            _CTX_RECON,
            "recon",
        ),
        (
            _PATH_ONLY_PREFIX_RE
            + r"(?:actuator|server-status|telescope)"
            + _PATH_ONLY_SUFFIX_RE,
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
            _PATH_ONLY_PREFIX_RE
            + r"(?:geoserver|confluence|nifi|ScadaBR|pandora_console"
            r"|centreon|kylin|decisioncenter|evox|MagicInfo|metasys"
            r"|officescan|helpdesk|ignite)"
            + rf"(?:[.\-]{_PATH_ONLY_CHAR_RE}*)?"
            + _PATH_ONLY_SUFFIX_RE,
            _CTX_RECON,
            "recon",
        ),
        (
            _PATH_ONLY_PREFIX_RE + r"cgi-(?:bin|mod)" + _PATH_ONLY_SUFFIX_RE,
            _CTX_RECON,
            "recon",
        ),
        (
            _PATH_ONLY_PREFIX_RE
            + r"(?:HNAP1|IPCamDesc\.xml|SDK/webLanguage)"
            + _PATH_ONLY_SUFFIX_RE,
            _CTX_RECON,
            "recon",
        ),
        (
            _PATH_ONLY_PREFIX_RE + r"(?:language|languages)" + _PATH_ONLY_SUFFIX_RE,
            _CTX_RECON,
            "recon",
        ),
        (
            _PATH_ONLY_PREFIX_RE + r"(?:readme\.txt|README\.md|CHANGELOG|pom\.xml"
            r"|build\.gradle|appsettings\.json|crossdomain\.xml)"
            + rf"(?:\.{_PATH_ONLY_CHAR_RE}*)?"
            + _PATH_ONLY_SUFFIX_RE,
            _CTX_RECON,
            "recon",
        ),
        (
            _PATH_ONLY_PREFIX_RE + r"(?:sap|ise|nidp|cslu|rustfs|developmentserver"
            r"|fog/management|lms/db|json/login_session|sms_mp"
            r"|plugin/webs_model|wsman|am_bin)" + _PATH_ONLY_SUFFIX_RE,
            _CTX_RECON,
            "recon",
        ),
        (r"(?:nmaplowercheck|nice\s+ports|Trinity\.txt)", _CTX_RECON, "recon"),
        (
            _PATH_ONLY_PREFIX_RE + r"\.(?:openclaw|clawdbot)" + _PATH_ONLY_SUFFIX_RE,
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
            _PATH_ONLY_PREFIX_RE + r"inicio\.html?" + _PATH_ONLY_SUFFIX_RE,
            _CTX_RECON,
            "recon",
        ),
        (
            _PATH_ONLY_PREFIX_RE + r"(?:\.streamlit|\.gpt-pilot|\.aider|\.cursor"
            r"|\.windsurf|\.copilot|\.devcontainer)" + _PATH_ONLY_SUFFIX_RE,
            _CTX_RECON,
            "recon",
        ),
        (
            _PATH_ONLY_PREFIX_RE + r"(?:docker-compose|Dockerfile|Makefile|Vagrantfile"
            r"|Jenkinsfile|Procfile)(?:\.ya?ml)?" + _PATH_ONLY_SUFFIX_RE,
            _CTX_RECON,
            "recon",
        ),
        (
            _PATH_ONLY_PREFIX_RE + rf"{_PATH_ONLY_CHAR_RE}*(?:secrets?|credentials?)"
            r"\.(?:py|json|yml|yaml|toml|txt|env|xml|conf|cfg)" + _PATH_ONLY_SUFFIX_RE,
            _CTX_RECON,
            "recon",
        ),
        (
            _PATH_ONLY_PREFIX_RE + r"autodiscover" + _PATH_ONLY_SUFFIX_RE,
            _CTX_RECON,
            "recon",
        ),
        (
            _PATH_ONLY_PREFIX_RE + r"dns-query" + _PATH_ONLY_SUFFIX_RE,
            _CTX_RECON,
            "recon",
        ),
        (
            _PATH_ONLY_PREFIX_RE
            + r"\.git/(?:refs|index|HEAD|objects|logs)"
            + _PATH_ONLY_SUFFIX_RE,
            _CTX_RECON,
            "recon",
        ),
        (
            r"(?:__proto__|constructor)\s*(?:\[\s*[\"']prototype[\"']\s*\]|\.\s*prototype)|[\"']__proto__[\"']\s*:",
            _CTX_PROTO_POLLUTION,
            "proto_pollution",
        ),
        (
            r"System\.Diagnostics\.Process\.Start\s*\(|System\.Reflection\.|Assembly\.Load\s*\(",
            _CTX_CODE_INJECTION,
            "code_injection",
        ),
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
    ) -> str:
        state = self._resolve_state(state)
        preprocessor = state.preprocessor
        if not preprocessor:
            max_length = getattr(
                self._config, "detection_max_content_length", _DEFAULT_MAX_SCAN_LENGTH
            )
            return content[:max_length]

        context_preprocessor = ContentPreprocessor(
            max_content_length=preprocessor.max_content_length,
            preserve_attack_patterns=preprocessor.preserve_attack_patterns,
            agent_handler=self.agent_handler,
            correlation_id=correlation_id,
        )
        return await context_preprocessor.preprocess(content)

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
        timeout_occurred = False
        compiler = state.compiler

        if compiler:
            if category == "custom":
                safe_matcher = compiler.create_safe_matcher(pattern)
                match = safe_matcher(content)
                timeout_threshold = 0.9 * compiler.default_timeout
                if (
                    match is None
                    and time.monotonic() - pattern_start >= timeout_threshold
                ):
                    timeout_occurred = True
                    logger.warning(f"Pattern timeout: {pattern.pattern[:50]}...")

                if match:
                    threat = _build_regex_threat(
                        pattern, match, category, pattern_start, context
                    )
                    if threat:
                        return threat, timeout_occurred
            else:
                threat = _first_accepted_regex_threat(
                    pattern.finditer(content), pattern, category, pattern_start, context
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
    def _normalize_context(context: str) -> str:
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
            ):
                continue

            pattern_start = time.monotonic()

            threat, timeout_occurred = await self._check_regex_pattern(
                pattern,
                content,
                ip_address,
                pattern_start,
                category,
                state=state,
                context=normalized,
            )

            if timeout_occurred:
                timeouts.append(pattern.pattern)

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
        self, content: str, *, state: _DetectionState | None = None
    ) -> tuple[list[dict], float]:
        state = self._resolve_state(state)
        semantic_analyzer = state.semantic_analyzer
        if not semantic_analyzer:
            return [], 0.0

        semantic_threshold = state.semantic_threshold
        semantic_analysis = semantic_analyzer.analyze(content)
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

        processed_content = await self._preprocess_content(
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

        semantic_threats, semantic_score = await self._check_semantic_threats(
            processed_content, state=state
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
            content_preview=content[:100] if len(content) > 100 else content,
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
        is_safe, reason = await asyncio.to_thread(
            compiler.validate_pattern_safety, pattern
        )
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
                "summary": performance_monitor.get_summary_stats(),
                "slow_patterns": performance_monitor.get_slow_patterns(),
                "problematic_patterns": (
                    performance_monitor.get_problematic_patterns()
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
                cls._instance._performance_monitor.pattern_stats.clear()
                cls._instance._performance_monitor.recent_metrics.clear()

            cls._config = None


sus_patterns_handler = SusPatternsManager()
