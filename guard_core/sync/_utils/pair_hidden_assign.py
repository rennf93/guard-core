import re

from guard_core.sync._utils.pair_value_scan import (
    _HARD_SEP_CHARS,
    _JSON_START_CHARS,
    _QUOTE_CHARS,
    _bounded_percent_decode,
    _has_undecoded_percent_escape,
    _redact_embedded_json_value,
    _redact_sensitive_pair_value,
    _skip_soft_whitespace,
)

_REDACTED_MARKER = "[REDACTED]"

_HIDDEN_ASSIGN_TOKEN_LENGTHS = (3, 5, 7)
_SMUGGLED_SEPARATOR_RE = re.compile(r"[&;,?|]")
_ESCAPED_GAP_RE = re.compile(r"\\+([tnrfvb\"']|x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4})")


def _escaped_gap_length(text: str, pos: int) -> int:
    match = _ESCAPED_GAP_RE.match(text, pos)
    if match is None:
        return 0
    body = match.group(1)
    if body[0] in "xu":
        decoded = chr(int(body[1:], 16))
        if not (decoded.isspace() or decoded in _QUOTE_CHARS or ord(decoded) < 32):
            return 0
    return match.end() - pos


def _match_hidden_assign_token(text: str, pos: int) -> int | None:
    if text[pos : pos + 1] in ("=", ":"):
        return pos + 1
    n = len(text)
    for length in _HIDDEN_ASSIGN_TOKEN_LENGTHS:
        end = pos + length
        if end > n:
            break
        if _bounded_percent_decode(text[pos:end]) in ("=", ":"):
            return end
    return None


def _skip_hidden_assign_gap(text: str, pos: int) -> int:
    cursor = pos
    while True:
        next_cursor = _skip_soft_whitespace(text, cursor)
        next_cursor += _escaped_gap_length(text, next_cursor)
        if next_cursor == cursor:
            return cursor
        cursor = next_cursor


def _match_hidden_assign(text: str, pos: int) -> int | None:
    cursor = _skip_hidden_assign_gap(text, pos)
    matched = False
    while True:
        token_end = _match_hidden_assign_token(text, cursor)
        if token_end is None:
            break
        matched = True
        cursor = _skip_hidden_assign_gap(text, token_end)
    return cursor if matched else None


def _skip_assign_run_tail(token: str, pos: int) -> int:
    n = len(token)
    i = pos
    while i < n and token[i] in ("=", ":"):
        i += 1
        while i < n and token[i] in (" ", "\t"):
            i += 1
    return i


def _hidden_pair_split(token: str) -> tuple[str, int] | None:
    eq_pos = token.find("=")
    colon_pos = token.find(":")
    candidates = [pos for pos in (eq_pos, colon_pos) if pos != -1]
    if not candidates:
        return None
    split_pos = min(candidates)
    value_pos = _skip_assign_run_tail(token, split_pos)
    return token[:split_pos].strip().lower(), value_pos


def _redact_adjacent_sensitive_value(text: str, pos: int) -> tuple[str, int] | None:
    value_start = _skip_soft_whitespace(text, pos)
    if value_start >= len(text) or text[value_start] in _HARD_SEP_CHARS:
        return None
    leading_ws = text[pos:value_start]
    replacement, end = _redact_sensitive_pair_value(text, value_start)
    return leading_ws + replacement, end


def _open_quote_at_end(replacement: str) -> str:
    if not replacement.endswith(_REDACTED_MARKER):
        return ""
    quote_pos = len(replacement) - len(_REDACTED_MARKER) - 1
    if quote_pos < 0:
        return ""
    candidate = replacement[quote_pos]
    return candidate if candidate in _QUOTE_CHARS else ""


def _close_dangling_quote_in_continuation(
    redacted_local: str, continuation: str
) -> tuple[str, int]:
    quote_char = _open_quote_at_end(redacted_local)
    if not quote_char or not continuation:
        return redacted_local, 0
    idx = continuation.find(quote_char)
    if idx == -1:
        return redacted_local, len(continuation)
    return redacted_local + quote_char, idx + 1


def _rescan_decoded_run(
    decoded_run: str,
    continuation: str,
    sensitive: frozenset[str],
    sensitive_body_fields: frozenset[str],
    max_depth: int,
) -> tuple[str, int] | None:
    if decoded_run[:1] in _JSON_START_CHARS:
        whole_json = _redact_embedded_json_value(
            decoded_run, sensitive, sensitive_body_fields, max_depth
        )
        if whole_json is not None:
            return whole_json, 0
    if _has_undecoded_percent_escape(decoded_run):
        return None

    from guard_core.sync._utils.pair_redaction import _redact_pairs_in_text_ex

    redacted_local, dangling = _redact_pairs_in_text_ex(
        decoded_run, sensitive, sensitive_body_fields, max_depth
    )
    if redacted_local == decoded_run:
        return None
    if _open_quote_at_end(redacted_local):
        return _close_dangling_quote_in_continuation(redacted_local, continuation)
    if dangling:
        adjacent = _redact_adjacent_sensitive_value(continuation, 0)
        if adjacent is not None:
            return redacted_local + adjacent[0], adjacent[1]
    return redacted_local, 0


def _redact_hidden_encoded_pair(
    text: str,
    run_end: int,
    raw_run: str,
    sensitive: frozenset[str],
    sensitive_body_fields: frozenset[str] = frozenset(),
    max_depth: int = 32,
) -> tuple[str, int] | None:
    decoded_run = _bounded_percent_decode(raw_run)
    tokens = _SMUGGLED_SEPARATOR_RE.split(decoded_run)
    for token in tokens:
        split = _hidden_pair_split(token)
        if split is None:
            continue
        name, value_pos = split
        if name in sensitive or _has_undecoded_percent_escape(name):
            if len(tokens) == 1 and value_pos >= len(token):
                adjacent = _redact_adjacent_sensitive_value(text, run_end)
                if adjacent is not None:
                    return _REDACTED_MARKER + adjacent[0], adjacent[1]
            return _REDACTED_MARKER, run_end
    if decoded_run != raw_run:
        rescanned = _rescan_decoded_run(
            decoded_run,
            text[run_end:],
            sensitive,
            sensitive_body_fields,
            max_depth,
        )
        if rescanned is not None:
            replacement, consumed = rescanned
            return replacement, run_end + consumed
    return None


def _handle_no_literal_assign(
    text: str,
    run_end: int,
    raw_run: str,
    sensitive: frozenset[str],
    out: list[str],
    flush_start: int,
    i: int,
    sensitive_body_fields: frozenset[str] = frozenset(),
    max_depth: int = 32,
) -> tuple[int, int, int | None]:
    value_start = _match_hidden_assign(text, run_end)
    if value_start is not None:
        return i, flush_start, value_start
    result = _redact_hidden_encoded_pair(
        text, run_end, raw_run, sensitive, sensitive_body_fields, max_depth
    )
    if result is None:
        return run_end, flush_start, None
    replacement, end = result
    out.append(text[flush_start:i])
    out.append(replacement)
    return end, end, None
