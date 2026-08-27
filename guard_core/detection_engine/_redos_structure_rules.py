import re

from guard_core.detection_engine._redos_structure_primitives import (
    _MAX_GROUP_NESTING_DEPTH,
    GroupNestingTooDeep,
    _branch_is_unbounded_single,
    _find_group_end,
    _iter_quantified_group_bodies,
    _normalize_group_inner,
    _outer_quantifier_len,
    _overlapping_literal_branches,
    _skip_char_class,
    _split_top_level_alternations,
    _strip_escapes_and_char_classes,
)

_NESTING_DEPTH_REJECTION_REASON = (
    f"pattern exceeds the maximum group nesting depth of "
    f"{_MAX_GROUP_NESTING_DEPTH} the ReDoS structural analyzer supports"
)


def _nested_body_is_unbounded(inner: str) -> bool:
    stripped_inner = _strip_escapes_and_char_classes(inner)
    if any(_branch_is_unbounded_single(b) for b in stripped_inner.split("|")):
        return True
    return _overlapping_literal_branches(inner)


def _detect_nested_unbounded_quantifier(pattern: str) -> str | None:
    try:
        for start, end, inner in _iter_quantified_group_bodies(pattern):
            if _nested_body_is_unbounded(inner):
                return pattern[start:end]
    except GroupNestingTooDeep:
        return _NESTING_DEPTH_REJECTION_REASON
    return None


_BROAD_SHORTHAND_ESCAPE_LETTERS = frozenset("SWD")
_ALREADY_BROAD_SHORTHAND_IN_NEGATED_CLASS_RE = re.compile(r"\\[SWD]")


def _is_broad_char_class_inner(inner: str) -> bool:
    if inner.startswith("^"):
        excluded = inner[1:]
        return _ALREADY_BROAD_SHORTHAND_IN_NEGATED_CLASS_RE.search(excluded) is None
    return inner in ("\\s\\S", "\\S\\s")


def _broad_atom_span(pattern: str, i: int) -> tuple[int, bool]:
    c = pattern[i]
    n = len(pattern)
    if c == "\\" and i + 1 < n:
        return i + 2, pattern[i + 1] in _BROAD_SHORTHAND_ESCAPE_LETTERS
    if c == "[":
        j = _skip_char_class(pattern, i)
        return j, _is_broad_char_class_inner(pattern[i + 1 : j - 1])
    if c == ".":
        return i + 1, True
    return i + 1, False


def _broad_unbounded_run_at(pattern: str, depth: int) -> tuple[int, list[str]]:
    if depth > _MAX_GROUP_NESTING_DEPTH:
        raise GroupNestingTooDeep(_MAX_GROUP_NESTING_DEPTH)
    count = 0
    spans: list[str] = []
    i = 0
    n = len(pattern)
    while i < n:
        if pattern[i] == "(":
            j = _find_group_end(pattern, i)
            if j is None:
                i += 1
                continue
            inner = _normalize_group_inner(pattern[i + 1 : j - 1])
            if inner is not None:
                branch_results = [
                    _broad_unbounded_run_at(branch, depth + 1)
                    for branch in _split_top_level_alternations(inner)
                ]
                best_count, best_spans = max(branch_results, key=lambda r: r[0])
                count += best_count
                spans.extend(best_spans)
            i = j
            continue
        atom_end, is_broad = _broad_atom_span(pattern, i)
        if is_broad and _outer_quantifier_len(pattern, atom_end) > 0:
            count += 1
            spans.append(pattern[i:atom_end])
        i = atom_end
    return count, spans


def _detect_adjacent_broad_unbounded_quantifiers(pattern: str) -> str | None:
    try:
        count, spans = _broad_unbounded_run_at(pattern, 0)
    except GroupNestingTooDeep:
        return _NESTING_DEPTH_REJECTION_REASON
    if count >= 2:
        return " and ".join(spans[:2])
    return None
