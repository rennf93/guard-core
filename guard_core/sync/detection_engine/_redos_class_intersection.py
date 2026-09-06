from __future__ import annotations

from collections.abc import Callable

from guard_core.sync.detection_engine._redos_parse_slots import (
    _ALPHABET,
    _REQUIRED_CANDIDATE_CODE_POINTS,
    _NonPairingSlot,
    _PairingAtom,
    _pattern_slots,
    _Slot,
)

_MAX_GROUP_CROSSING_DEPTH = 16
_ALPHABET_SORTED: tuple[str, ...] = tuple(sorted(_ALPHABET))
_STRAY_CANDIDATES: tuple[str, ...] = (
    "\x00",
    "<",
    ">",
    "\n",
    '"',
    "'",
    " ",
    "a",
    "0",
    "-",
    "\x7f",
)


def _crossing_slot_narrows(
    slot: _Slot, shared: frozenset[str], depth: int
) -> frozenset[str] | None:
    if isinstance(slot, _PairingAtom):
        if slot.allows_zero:
            return shared
        overlap = slot.charset & shared
        return overlap if overlap else None
    if not slot.is_boundary:
        return shared
    if slot.inner is None:
        return None
    crossing = _group_crossing_result(slot.inner, shared, depth + 1)
    return shared if crossing is not None else None


def _alternative_crossing(
    alt_slots: list[_Slot], shared: frozenset[str], depth: int
) -> frozenset[str] | None:
    local = shared
    for slot in alt_slots:
        narrowed = _crossing_slot_narrows(slot, local, depth)
        if narrowed is None:
            return None
        local = narrowed
    return local


def _group_crossing_result(
    alternatives: list[list[_Slot]], shared: frozenset[str], depth: int
) -> frozenset[str] | None:
    if depth > _MAX_GROUP_CROSSING_DEPTH:
        return None
    crossed = [
        result
        for alt in alternatives
        if (result := _alternative_crossing(alt, shared, depth)) is not None
    ]
    if not crossed:
        return None
    return frozenset[str]().union(*crossed)


def _cross_non_pairing_slot(
    slot: _NonPairingSlot, shared: frozenset[str]
) -> tuple[frozenset[str], str | None] | None:
    if slot.inner is None:
        return (shared, None) if not slot.is_boundary else None
    crossing = _group_crossing_result(slot.inner, shared, 0)
    if slot.is_boundary:
        if crossing is None:
            return None
        fill = sorted(crossing)[0] if slot.unbounded else None
        return crossing, fill
    if crossing is None:
        return shared, None
    fill = sorted(crossing)[0] if slot.unbounded else None
    return shared, fill


def _stray_from_fixed_alphabet(excluded: frozenset[str]) -> str | None:
    ascii_candidate = next((c for c in _STRAY_CANDIDATES if c not in excluded), None)
    if ascii_candidate is not None:
        return ascii_candidate
    return next((c for c in _ALPHABET_SORTED if c not in excluded), None)


def _stray_from_exact_predicates(
    left_predicate: Callable[[int], bool] | None,
    right_predicate: Callable[[int], bool] | None,
    extra_candidates: frozenset[int],
) -> str | None:
    if left_predicate is None or right_predicate is None:
        return None
    pool = sorted(set(_REQUIRED_CANDIDATE_CODE_POINTS) | extra_candidates)
    for code_point in pool:
        if not left_predicate(code_point) and not right_predicate(code_point):
            return chr(code_point)
    return None


def _stray_for_pair(
    left_charset: frozenset[str],
    right_charset: frozenset[str],
    left_predicate: Callable[[int], bool] | None = None,
    right_predicate: Callable[[int], bool] | None = None,
    extra_candidates: frozenset[int] = frozenset(),
) -> str:
    fixed_stray = _stray_from_fixed_alphabet(left_charset | right_charset)
    if fixed_stray is not None:
        return fixed_stray
    exact_stray = _stray_from_exact_predicates(
        left_predicate, right_predicate, extra_candidates
    )
    if exact_stray is not None:
        return exact_stray
    return "\x00"


def _and_predicate(
    first: Callable[[int], bool], second: Callable[[int], bool]
) -> Callable[[int], bool]:
    return lambda code_point: first(code_point) and second(code_point)


def _narrow_exact_state(
    predicate: Callable[[int], bool] | None,
    candidates: frozenset[int],
    slot: _PairingAtom,
) -> tuple[Callable[[int], bool] | None, frozenset[int]]:
    if predicate is None or slot.predicate is None:
        return None, frozenset()
    return _and_predicate(predicate, slot.predicate), candidates | slot.candidates


def _exact_overlap_fill(
    predicate: Callable[[int], bool] | None,
    candidates: frozenset[int],
    right: _PairingAtom,
) -> str | None:
    if predicate is None or right.predicate is None:
        return None
    pool = sorted(set(_REQUIRED_CANDIDATE_CODE_POINTS) | candidates | right.candidates)
    for code_point in pool:
        if predicate(code_point) and right.predicate(code_point):
            return chr(code_point)
    return None


def _append_pairing_unit(
    units: list[tuple[str, str]],
    left: _PairingAtom,
    slot: _PairingAtom,
    left_charset: frozenset[str],
    fill: str,
) -> None:
    stray = _stray_for_pair(
        left_charset,
        slot.charset,
        left.predicate,
        slot.predicate,
        left.candidates | slot.candidates,
    )
    units.append((fill, stray))


def _advance_pairing_chain(
    units: list[tuple[str, str]],
    left: _PairingAtom,
    left_charset: frozenset[str],
    slot: _PairingAtom,
    shared: frozenset[str],
    exact_predicate: Callable[[int], bool] | None,
    exact_candidates: frozenset[int],
) -> tuple[frozenset[str], Callable[[int], bool] | None, frozenset[int], bool]:
    overlap = slot.charset & shared
    if overlap:
        if slot.unbounded:
            _append_pairing_unit(units, left, slot, left_charset, sorted(overlap)[0])
        if not slot.allows_zero:
            shared = overlap
            exact_predicate, exact_candidates = _narrow_exact_state(
                exact_predicate, exact_candidates, slot
            )
        return shared, exact_predicate, exact_candidates, False
    exact_fill = _exact_overlap_fill(exact_predicate, exact_candidates, slot)
    if exact_fill is None:
        return shared, exact_predicate, exact_candidates, not slot.allows_zero
    if slot.unbounded:
        _append_pairing_unit(units, left, slot, left_charset, exact_fill)
    if not slot.allows_zero:
        shared = overlap
        exact_predicate, exact_candidates = None, frozenset()
    return shared, exact_predicate, exact_candidates, False


def _pairing_units_from(slots: list[_Slot], start: int) -> list[tuple[str, str]]:
    left = slots[start]
    if not isinstance(left, _PairingAtom):
        return []
    left_charset = left.charset
    shared = left_charset
    exact_predicate = left.predicate
    exact_candidates = left.candidates
    units: list[tuple[str, str]] = []
    for slot in slots[start + 1 :]:
        if isinstance(slot, _NonPairingSlot):
            crossed = _cross_non_pairing_slot(slot, shared)
            if crossed is None:
                break
            shared, fill = crossed
            exact_predicate, exact_candidates = None, frozenset()
            if fill is not None:
                units.append((fill, _stray_for_pair(left_charset, shared)))
            continue
        shared, exact_predicate, exact_candidates, should_stop = _advance_pairing_chain(
            units,
            left,
            left_charset,
            slot,
            shared,
            exact_predicate,
            exact_candidates,
        )
        if should_stop:
            break
    return units


def _flatten_alternatives(alternatives: list[list[_Slot]]) -> list[_Slot]:
    if len(alternatives) == 1:
        return alternatives[0]
    flat: list[_Slot] = []
    for index, alt in enumerate(alternatives):
        if index:
            flat.append(_NonPairingSlot(True, None))
        flat.extend(alt)
    return flat


def _units_in_group_alternatives(
    alternatives: list[list[_Slot]],
) -> list[tuple[str, str]]:
    return _units_in_slots(_flatten_alternatives(alternatives))


def _units_in_slots(slots: list[_Slot]) -> list[tuple[str, str]]:
    units: list[tuple[str, str]] = []
    for index, slot in enumerate(slots):
        if isinstance(slot, _NonPairingSlot):
            if slot.inner is not None:
                units.extend(_units_in_group_alternatives(slot.inner))
            continue
        if slot.unbounded:
            units.extend(_pairing_units_from(slots, index))
    return units


def _class_intersection_probe_units(pattern: str, flags: int) -> list[tuple[str, str]]:
    slots = _pattern_slots(pattern, flags)
    if slots is None:
        return []
    return _units_in_slots(slots)


def _class_intersection_fills(pattern: str, flags: int) -> list[str]:
    return [fill for fill, _stray in _class_intersection_probe_units(pattern, flags)]
