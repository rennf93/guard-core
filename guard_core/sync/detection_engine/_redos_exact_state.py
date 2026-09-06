from __future__ import annotations

from guard_core.sync.detection_engine._redos_intervals import _IntervalSet
from guard_core.sync.detection_engine._redos_parse_slots import _PairingAtom, _Slot

_MAX_GROUP_CROSSING_DEPTH = 16


def _narrow_exact_state_raw(
    state: _IntervalSet | None, right: _IntervalSet | None
) -> _IntervalSet | None:
    if state is None or right is None:
        return None
    return state.intersection(right)


def _exact_overlap_fill_raw(
    state: _IntervalSet | None, right: _IntervalSet | None
) -> str | None:
    if state is None or right is None:
        return None
    member = state.intersection(right).first_member()
    return chr(member) if member is not None else None


def _isolated_alternative_exact_state(
    alt_slots: list[_Slot], depth: int
) -> _IntervalSet | None:
    state: _IntervalSet | None = _IntervalSet.full()
    for slot in alt_slots:
        if isinstance(slot, _PairingAtom):
            if slot.allows_zero:
                continue
            state = _narrow_exact_state_raw(state, slot.intervals)
        elif slot.is_boundary:
            if slot.inner is None:
                return None
            group_state = _isolated_group_exact_state(slot.inner, depth + 1)
            state = _narrow_exact_state_raw(state, group_state)
        if state is None:
            return None
    return state


def _isolated_group_exact_state(
    alternatives: list[list[_Slot]], depth: int
) -> _IntervalSet | None:
    if depth > _MAX_GROUP_CROSSING_DEPTH:
        return None
    combined: _IntervalSet | None = None
    for alt in alternatives:
        alt_state = _isolated_alternative_exact_state(alt, depth)
        if alt_state is None:
            continue
        combined = alt_state if combined is None else combined.union(alt_state)
    return combined
