import re
from collections.abc import Iterator

from guard_core.detection_engine.scan_window import bounded_finditer
from guard_core.handlers._suspatterns_sources import (
    _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE,
    _LDAP_NULL_BYTE_ATTR_CONTINUATION_CHAR_RE,
    _LDAP_NULL_BYTE_ATTR_LEAD_CHAR_RE,
    _LDAP_NULL_BYTE_VALUE_CHAR_RE,
)

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
    r"(?:\A|[;,:\n])"
    + _FILE_UPLOAD_ATTR_EQUALS_WHITESPACE_RE
    + r"filename"
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
    r"\{\{(?![^\}]*\d{4}-\d{1,2}-\d{1,2}(?!\d))"
    r"(?=[^\}]*(?:@[\w.]+@|\b\w+\(\s*\)"
    r"|['\"]?\d+['\"]?\s*[*/%+\-]\s*['\"]?\d+['\"]?))"
    r"[^\}]*\}\}"
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
