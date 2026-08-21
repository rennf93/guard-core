from guard_core.sync.detection_engine._redos_structure import (
    _outer_quantifier_len,
    _skip_char_class,
)

_PREFIX_RESET_CHARS = frozenset("()|^$")
_TERMINATOR_NON_LITERAL_LEADERS = frozenset("()|^$.*+?{")


def _skip_symbol_quantifier_at(text: str, k: int) -> int:
    end = k + 1
    if end < len(text) and text[end] == "?":
        end += 1
    return end - k


def _skip_brace_quantifier_at(text: str, k: int) -> int:
    end_brace = text.find("}", k)
    if end_brace == -1:
        return 0
    parts = text[k + 1 : end_brace].split(",")
    if not all(p.isdigit() for p in parts if p != "") or all(p == "" for p in parts):
        return 0
    end = end_brace + 1
    if end < len(text) and text[end] == "?":
        end += 1
    return end - k


def _skip_quantifier_at(text: str, k: int) -> int:
    if k >= len(text):
        return 0
    c = text[k]
    if c in "*+?":
        return _skip_symbol_quantifier_at(text, k)
    if c == "{":
        return _skip_brace_quantifier_at(text, k)
    return 0


def _quantifier_at_allows_zero(text: str, k: int) -> bool:
    if _skip_quantifier_at(text, k) == 0:
        return False
    c = text[k]
    if c in "*?":
        return True
    if c != "{":
        return False
    end_brace = text.find("}", k)
    low = text[k + 1 : end_brace].split(",")[0]
    return low in ("", "0")


def _terminator_chars_at(text: str, j: int) -> set[str] | None:
    if j >= len(text):
        return None
    c = text[j]
    if c == "[":
        end = _skip_char_class(text, j)
        inner = text[j + 1 : end - 1]
        if inner.startswith("^") or not inner:
            return None
        return set(inner)
    if c == "\\" and j + 1 < len(text):
        nxt = text[j + 1]
        return None if nxt.isalnum() else {nxt}
    if c in _TERMINATOR_NON_LITERAL_LEADERS:
        return None
    return {c}


def _broad_scan_excluded_chars(pattern: str, i: int) -> tuple[int, set[str] | None]:
    c = pattern[i]
    if c == ".":
        return i + 1, set()
    j = _skip_char_class(pattern, i)
    inner = pattern[i + 1 : j - 1]
    if not inner.startswith("^"):
        return j, None
    return j, set(inner[1:])


def _class_terminator_finding(
    pattern: str, i: int, scan_end: int, prefix_chars: set[str], excluded: set[str]
) -> str | None:
    if _outer_quantifier_len(pattern, scan_end) == 0:
        return None
    term_pos = scan_end + _skip_quantifier_at(pattern, scan_end)
    terminator_chars = _terminator_chars_at(pattern, term_pos)
    if (
        terminator_chars
        and prefix_chars
        and not (prefix_chars & excluded)
        and not (prefix_chars & terminator_chars)
    ):
        return f"{pattern[i:scan_end]} preceded by {''.join(sorted(prefix_chars))}"
    return None


def _unreachable_terminator_broad_scan_step(
    pattern: str, i: int, prefix_chars: set[str]
) -> tuple[int, set[str], str | None]:
    scan_end, excluded = _broad_scan_excluded_chars(pattern, i)
    if excluded is None:
        return scan_end, set(), None
    finding = _class_terminator_finding(pattern, i, scan_end, prefix_chars, excluded)
    if finding is not None:
        return scan_end, prefix_chars, finding
    next_i = scan_end + _skip_quantifier_at(pattern, scan_end)
    return next_i, set(), None


def _unreachable_terminator_escape_step(
    pattern: str, i: int, prefix_chars: set[str]
) -> tuple[int, set[str]]:
    nxt = pattern[i + 1]
    token_end = i + 2
    if not nxt.isalnum():
        next_prefix = prefix_chars | {nxt}
    elif _quantifier_at_allows_zero(pattern, token_end):
        next_prefix = prefix_chars
    else:
        next_prefix = set()
    return token_end + _skip_quantifier_at(pattern, token_end), next_prefix


def _unreachable_terminator_group_open_step(
    pattern: str, i: int, prefix_chars: set[str]
) -> tuple[int, set[str]]:
    if pattern[i + 1 : i + 3] == "?:":
        return i + 3, prefix_chars
    if i + 1 < len(pattern) and pattern[i + 1] == "?":
        end_paren = pattern.find(")", i)
        next_i = end_paren + 1 if end_paren != -1 else i + 1
        return next_i, set()
    return i + 1, set()


def _unreachable_terminator_step(
    pattern: str, i: int, prefix_chars: set[str]
) -> tuple[int, set[str], str | None]:
    c = pattern[i]
    if c == "(":
        next_i, next_prefix = _unreachable_terminator_group_open_step(
            pattern, i, prefix_chars
        )
        return next_i, next_prefix, None
    if c in _PREFIX_RESET_CHARS:
        return i + 1, set(), None
    if c in "[.":
        return _unreachable_terminator_broad_scan_step(pattern, i, prefix_chars)
    if c == "\\" and i + 1 < len(pattern):
        next_i, next_prefix = _unreachable_terminator_escape_step(
            pattern, i, prefix_chars
        )
        return next_i, next_prefix, None
    return i + 1 + _skip_quantifier_at(pattern, i + 1), prefix_chars | {c}, None


def _detect_unreachable_terminator_scan(pattern: str) -> str | None:
    prefix_chars: set[str] = set()
    i = 0
    n = len(pattern)
    while i < n:
        i, prefix_chars, finding = _unreachable_terminator_step(
            pattern, i, prefix_chars
        )
        if finding is not None:
            return finding
    return None
