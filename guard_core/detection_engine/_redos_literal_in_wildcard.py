from guard_core.detection_engine._redos_ambiguous_tail import _atom_char_set
from guard_core.detection_engine._redos_structure import (
    _outer_quantifier_len,
    _skip_char_class,
)


def _literal_run_at(pattern: str, i: int) -> tuple[str, int]:
    j = i
    n = len(pattern)
    while j < n and (pattern[j].isalnum() or pattern[j] == "-"):
        j += 1
    return pattern[i:j], j


def _wildcard_absorbs_literal(pattern: str, i: int, end: int) -> str | None:
    qlen = _outer_quantifier_len(pattern, end)
    if qlen == 0:
        return None
    class_chars = _atom_char_set(pattern[i:end])
    if not class_chars:
        return None
    literal, _literal_end = _literal_run_at(pattern, end + qlen)
    if len(literal) < 2 or not set(literal) <= class_chars:
        return None
    return f"{pattern[i : end + qlen]} then literal {literal!r}"


def _detect_ambiguous_literal_boundary(pattern: str) -> str | None:
    i = 0
    n = len(pattern)
    while i < n:
        if pattern[i] != "[":
            i += 1
            continue
        end = _skip_char_class(pattern, i)
        finding = _wildcard_absorbs_literal(pattern, i, end)
        if finding is not None:
            return finding
        i = end
    return None
