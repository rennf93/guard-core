from __future__ import annotations

import importlib
import re
from typing import Any, NamedTuple


def _import_regex_parser_module() -> Any:
    try:
        return importlib.import_module("re._parser")
    except ImportError:
        return importlib.import_module("sre_parse")


_regex_parser: Any = _import_regex_parser_module()

_MAX_GROUP_CROSSING_DEPTH = 16
_ALPHABET_EXTRA_CODE_POINTS: tuple[int, ...] = (0x100, 0x400, 0x4E00, 0xFFFD, 0x1F600)
_ALPHABET: frozenset[str] = frozenset(chr(c) for c in range(256)) | frozenset(
    chr(c) for c in _ALPHABET_EXTRA_CODE_POINTS
)
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


class _PairingAtom(NamedTuple):
    charset: frozenset[str]
    allows_zero: bool
    unbounded: bool


class _NonPairingSlot(NamedTuple):
    is_boundary: bool
    inner: list[list[_Slot]] | None
    unbounded: bool = False


_Slot = _PairingAtom | _NonPairingSlot

_PAIRING_OPS = frozenset(
    {
        _regex_parser.LITERAL,
        _regex_parser.NOT_LITERAL,
        _regex_parser.IN,
        _regex_parser.ANY,
        _regex_parser.CATEGORY,
    }
)
_POSSESSIVE_REPEAT = getattr(_regex_parser, "POSSESSIVE_REPEAT", None)
_ATOMIC_GROUP = getattr(_regex_parser, "ATOMIC_GROUP", None)
_REPEAT_OPS = frozenset(
    {_regex_parser.MAX_REPEAT, _regex_parser.MIN_REPEAT, _POSSESSIVE_REPEAT}
)
_ASSERT_OPS = frozenset({_regex_parser.ASSERT, _regex_parser.ASSERT_NOT})
_CATEGORY_ESCAPES: dict[Any, str] = {
    _regex_parser.CATEGORY_DIGIT: r"\d",
    _regex_parser.CATEGORY_NOT_DIGIT: r"\D",
    _regex_parser.CATEGORY_SPACE: r"\s",
    _regex_parser.CATEGORY_NOT_SPACE: r"\S",
    _regex_parser.CATEGORY_WORD: r"\w",
    _regex_parser.CATEGORY_NOT_WORD: r"\W",
}


def _parse_pattern(pattern: str, flags: int) -> Any:
    return _regex_parser.parse(pattern, flags)


def _ignorecase_fold(charset: frozenset[str], flags: int) -> frozenset[str]:
    if not flags & re.IGNORECASE:
        return charset
    folded: set[str] = set(charset)
    for ch in charset:
        for variant in (ch.lower(), ch.upper(), ch.casefold()):
            if len(variant) == 1:
                folded.add(variant)
    return frozenset(ch for ch in folded if ch in _ALPHABET)


def _category_charset(category: Any, flags: int) -> frozenset[str]:
    escape = _CATEGORY_ESCAPES.get(category)
    if escape is None:
        return _ALPHABET
    compiled = re.compile(escape, flags)
    return frozenset(ch for ch in _ALPHABET if compiled.fullmatch(ch))


def _range_charset(low: int, high: int) -> frozenset[str]:
    return frozenset(ch for ch in _ALPHABET if low <= ord(ch) <= high)


def _literal_charset(code: int) -> frozenset[str]:
    return frozenset(ch for ch in _ALPHABET if ord(ch) == code)


def _class_item_charset(op: Any, av: Any, flags: int) -> frozenset[str]:
    if op is _regex_parser.LITERAL:
        return _ignorecase_fold(_literal_charset(av), flags)
    if op is _regex_parser.RANGE:
        return _ignorecase_fold(_range_charset(av[0], av[1]), flags)
    if op is _regex_parser.CATEGORY:
        return _category_charset(av, flags)
    return _ALPHABET


def _in_charset(items: list[tuple[Any, Any]], flags: int) -> frozenset[str]:
    if items and items[0][0] is _regex_parser.NEGATE:
        return _ALPHABET - _in_charset(items[1:], flags)
    result: frozenset[str] = frozenset()
    for op, av in items:
        result |= _class_item_charset(op, av, flags)
    return result


def _any_charset(flags: int) -> frozenset[str]:
    if flags & re.DOTALL:
        return _ALPHABET
    return _ALPHABET - {"\n"}


def _pairing_charset(op: Any, av: Any, flags: int) -> frozenset[str]:
    if op is _regex_parser.LITERAL:
        return _ignorecase_fold(_literal_charset(av), flags)
    if op is _regex_parser.NOT_LITERAL:
        return _ALPHABET - _ignorecase_fold(_literal_charset(av), flags)
    if op is _regex_parser.IN:
        return _in_charset(av, flags)
    if op is _regex_parser.ANY:
        return _any_charset(flags)
    return _category_charset(av, flags)


def _nonpairing_slot(
    op: Any, av: Any, flags: int, allows_zero: bool, unbounded: bool
) -> _NonPairingSlot:
    if op is _regex_parser.BRANCH:
        _ref, branches = av
        inner = [_walk_sequence(alt, flags) for alt in branches]
        return _NonPairingSlot(not allows_zero, inner, unbounded)
    if op is _regex_parser.SUBPATTERN:
        _group, add_flags, del_flags, body = av
        child_flags = (flags | add_flags) & ~del_flags
        return _NonPairingSlot(
            not allows_zero, _sequence_to_alternatives(body, child_flags), unbounded
        )
    if op is _ATOMIC_GROUP:
        return _NonPairingSlot(
            not allows_zero, _sequence_to_alternatives(av, flags), unbounded
        )
    if op in _ASSERT_OPS:
        _direction, body = av
        return _NonPairingSlot(False, _sequence_to_alternatives(body, flags), False)
    if op is _regex_parser.AT:
        return _NonPairingSlot(False, None, False)
    return _NonPairingSlot(True, None, False)


def _unrepeated_slot(op: Any, av: Any, flags: int) -> _Slot:
    if op in _PAIRING_OPS:
        return _PairingAtom(_pairing_charset(op, av, flags), False, False)
    return _nonpairing_slot(op, av, flags, False, False)


def _repeat_slot(av: tuple[int, int, list[Any]], flags: int) -> _Slot:
    low, high, body = av
    allows_zero = low == 0
    unbounded = high == _regex_parser.MAXREPEAT
    if len(body) == 1:
        op, item_av = body[0]
        if op in _PAIRING_OPS:
            return _PairingAtom(
                _pairing_charset(op, item_av, flags), allows_zero, unbounded
            )
        return _nonpairing_slot(op, item_av, flags, allows_zero, unbounded)
    return _NonPairingSlot(
        not allows_zero, _sequence_to_alternatives(body, flags), unbounded
    )


def _slot_for_flat_item(item: tuple[Any, Any], flags: int) -> _Slot:
    op, av = item
    if op in _REPEAT_OPS:
        return _repeat_slot(av, flags)
    return _unrepeated_slot(op, av, flags)


def _walk_sequence(items: list[Any], flags: int) -> list[_Slot]:
    return [_slot_for_flat_item(item, flags) for item in items]


def _sequence_to_alternatives(items: list[Any], flags: int) -> list[list[_Slot]]:
    if len(items) == 1 and items[0][0] is _regex_parser.BRANCH:
        _ref, branches = items[0][1]
        return [_walk_sequence(alt, flags) for alt in branches]
    return [_walk_sequence(items, flags)]


def _pattern_slots(pattern: str, flags: int) -> list[_Slot] | None:
    try:
        parsed = _parse_pattern(pattern, flags)
    except re.error:
        return None
    return _walk_sequence(parsed.data, parsed.state.flags)


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
    return next((c for c in _STRAY_CANDIDATES if c not in excluded), "\x00")


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
