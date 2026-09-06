from __future__ import annotations

from collections.abc import Callable

from guard_core.detection_engine._redos_parse_slots import (
    _REQUIRED_CANDIDATE_CODE_POINTS,
    _PairingAtom,
    _Slot,
)

_MAX_GROUP_CROSSING_DEPTH = 16


def _always_true(_code_point: int) -> bool:
    return True


def _and_predicate(
    first: Callable[[int], bool], second: Callable[[int], bool]
) -> Callable[[int], bool]:
    return lambda code_point: first(code_point) and second(code_point)


def _or_predicate(
    first: Callable[[int], bool], second: Callable[[int], bool]
) -> Callable[[int], bool]:
    return lambda code_point: first(code_point) or second(code_point)


def _narrow_exact_state_raw(
    predicate: Callable[[int], bool] | None,
    candidates: frozenset[int],
    right_predicate: Callable[[int], bool] | None,
    right_candidates: frozenset[int],
) -> tuple[Callable[[int], bool] | None, frozenset[int]]:
    if predicate is None or right_predicate is None:
        return None, frozenset()
    return _and_predicate(predicate, right_predicate), candidates | right_candidates


def _exact_overlap_fill_raw(
    predicate: Callable[[int], bool] | None,
    candidates: frozenset[int],
    right_predicate: Callable[[int], bool] | None,
    right_candidates: frozenset[int],
) -> str | None:
    if predicate is None or right_predicate is None:
        return None
    pool = sorted(set(_REQUIRED_CANDIDATE_CODE_POINTS) | candidates | right_candidates)
    for code_point in pool:
        if predicate(code_point) and right_predicate(code_point):
            return chr(code_point)
    return None


def _isolated_alternative_exact_state(
    alt_slots: list[_Slot], depth: int
) -> tuple[Callable[[int], bool] | None, frozenset[int]]:
    predicate: Callable[[int], bool] | None = _always_true
    candidates: frozenset[int] = frozenset()
    for slot in alt_slots:
        if isinstance(slot, _PairingAtom):
            if slot.allows_zero:
                continue
            predicate, candidates = _narrow_exact_state_raw(
                predicate, candidates, slot.predicate, slot.candidates
            )
        elif slot.is_boundary:
            if slot.inner is None:
                return None, frozenset()
            group_predicate, group_candidates = _isolated_group_exact_state(
                slot.inner, depth + 1
            )
            predicate, candidates = _narrow_exact_state_raw(
                predicate, candidates, group_predicate, group_candidates
            )
        if predicate is None:
            return None, frozenset()
    return predicate, candidates


def _isolated_group_exact_state(
    alternatives: list[list[_Slot]], depth: int
) -> tuple[Callable[[int], bool] | None, frozenset[int]]:
    if depth > _MAX_GROUP_CROSSING_DEPTH:
        return None, frozenset()
    combined_predicate: Callable[[int], bool] | None = None
    combined_candidates: frozenset[int] = frozenset()
    for alt in alternatives:
        alt_predicate, alt_candidates = _isolated_alternative_exact_state(alt, depth)
        if alt_predicate is None:
            continue
        combined_predicate = (
            alt_predicate
            if combined_predicate is None
            else _or_predicate(combined_predicate, alt_predicate)
        )
        combined_candidates |= alt_candidates
    return combined_predicate, combined_candidates
