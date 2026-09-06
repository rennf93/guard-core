from __future__ import annotations

from guard_core.detection_engine._redos_intervals import MAX_CODE_POINT, _IntervalSet

_FOLD_GROUPS: tuple[frozenset[int], ...] | None = None
_FOLD_GROUP_BY_CODE_POINT: dict[int, frozenset[int]] | None = None
_EXPAND_IGNORECASE_MEMBER_SCAN_CEILING = 4096


def _build_fold_groups() -> tuple[frozenset[int], ...]:
    parent: dict[int, int] = {}

    def find(code_point: int) -> int:
        parent.setdefault(code_point, code_point)
        root = code_point
        while parent[root] != root:
            root = parent[root]
        while parent[code_point] != root:
            parent[code_point], code_point = root, parent[code_point]
        return root

    def union(first: int, second: int) -> None:
        first_root, second_root = find(first), find(second)
        if first_root != second_root:
            parent[second_root] = first_root

    for code_point in range(MAX_CODE_POINT + 1):
        char = chr(code_point)
        for variant in (char.lower(), char.upper(), char.casefold()):
            if len(variant) == 1 and variant != char:
                union(code_point, ord(variant))

    groups: dict[int, set[int]] = {}
    for code_point in parent:
        groups.setdefault(find(code_point), set()).add(code_point)
    return tuple(frozenset(group) for group in groups.values() if len(group) > 1)


def _fold_groups() -> tuple[frozenset[int], ...]:
    global _FOLD_GROUPS
    if _FOLD_GROUPS is None:
        _FOLD_GROUPS = _build_fold_groups()
    return _FOLD_GROUPS


def _fold_group_by_code_point() -> dict[int, frozenset[int]]:
    global _FOLD_GROUP_BY_CODE_POINT
    if _FOLD_GROUP_BY_CODE_POINT is None:
        mapping: dict[int, frozenset[int]] = {}
        for group in _fold_groups():
            for code_point in group:
                mapping[code_point] = group
        _FOLD_GROUP_BY_CODE_POINT = mapping
    return _FOLD_GROUP_BY_CODE_POINT


def _fold_partners(group: frozenset[int], ascii_only: bool) -> frozenset[int]:
    if not ascii_only:
        return group
    return frozenset(code_point for code_point in group if code_point < 128)


def _expand_ignorecase_by_member_scan(
    interval_set: _IntervalSet, ascii_only: bool
) -> _IntervalSet:
    fold_map = _fold_group_by_code_point()
    result = interval_set
    seen_groups: set[frozenset[int]] = set()
    for low, high in interval_set._intervals:
        for code_point in range(low, high + 1):
            group = fold_map.get(code_point)
            if group is None or group in seen_groups:
                continue
            seen_groups.add(group)
            for partner in _fold_partners(group, ascii_only):
                if not result.contains(partner):
                    result = result.union(_IntervalSet.single(partner))
    return result


def _expand_ignorecase_by_group_scan(
    interval_set: _IntervalSet, ascii_only: bool
) -> _IntervalSet:
    result = interval_set
    for group in _fold_groups():
        candidates = _fold_partners(group, ascii_only)
        if len(candidates) < 2:
            continue
        if not any(interval_set.contains(code_point) for code_point in candidates):
            continue
        for code_point in candidates:
            if not result.contains(code_point):
                result = result.union(_IntervalSet.single(code_point))
    return result


def expand_ignorecase(interval_set: _IntervalSet, ascii_only: bool) -> _IntervalSet:
    member_count = sum(high - low + 1 for low, high in interval_set._intervals)
    if member_count <= _EXPAND_IGNORECASE_MEMBER_SCAN_CEILING:
        return _expand_ignorecase_by_member_scan(interval_set, ascii_only)
    return _expand_ignorecase_by_group_scan(interval_set, ascii_only)
