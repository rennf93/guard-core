from __future__ import annotations

from guard_core.sync.detection_engine._redos_parse_slots import (
    _ALPHABET,
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


def _stray_for_pair(left_charset: frozenset[str], right_charset: frozenset[str]) -> str:
    excluded = left_charset | right_charset
    ascii_candidate = next((c for c in _STRAY_CANDIDATES if c not in excluded), None)
    if ascii_candidate is not None:
        return ascii_candidate
    return next((c for c in _ALPHABET_SORTED if c not in excluded), "\x00")


def _pairing_units_from(slots: list[_Slot], start: int) -> list[tuple[str, str]]:
    left = slots[start]
    if not isinstance(left, _PairingAtom):
        return []
    left_charset = left.charset
    shared = left_charset
    units: list[tuple[str, str]] = []
    for slot in slots[start + 1 :]:
        if isinstance(slot, _NonPairingSlot):
            crossed = _cross_non_pairing_slot(slot, shared)
            if crossed is None:
                break
            shared, fill = crossed
            if fill is not None:
                units.append((fill, _stray_for_pair(left_charset, shared)))
            continue
        overlap = slot.charset & shared
        if not overlap:
            if not slot.allows_zero:
                break
            continue
        if slot.unbounded:
            units.append(
                (sorted(overlap)[0], _stray_for_pair(left_charset, slot.charset))
            )
        if not slot.allows_zero:
            shared = overlap
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
