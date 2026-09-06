from __future__ import annotations

import importlib
import re
from collections.abc import Callable
from typing import Any, NamedTuple


def _import_regex_parser_module() -> Any:
    try:
        return importlib.import_module("re._parser")
    except ImportError:
        return importlib.import_module("sre_parse")


_regex_parser: Any = _import_regex_parser_module()

_ALPHABET_EXTRA_CODE_POINTS: tuple[int, ...] = (0x100, 0x400, 0x4E00, 0xFFFD, 0x1F600)
_ALPHABET: frozenset[str] = frozenset(chr(c) for c in range(256)) | frozenset(
    chr(c) for c in _ALPHABET_EXTRA_CODE_POINTS
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


def _subpattern_body_and_flags(av: Any, flags: int) -> tuple[list[Any], int]:
    _group, add_flags, del_flags, body = av
    return body, (flags | add_flags) & ~del_flags


def _atomic_group_body_and_flags(av: Any, flags: int) -> tuple[list[Any], int]:
    return av, flags


_GROUP_LIKE_BODY_EXTRACTORS: dict[Any, Callable[[Any, int], tuple[list[Any], int]]] = {
    _regex_parser.SUBPATTERN: _subpattern_body_and_flags,
    _ATOMIC_GROUP: _atomic_group_body_and_flags,
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
    extractor = _GROUP_LIKE_BODY_EXTRACTORS.get(op)
    if extractor is not None:
        body, child_flags = extractor(av, flags)
        return _NonPairingSlot(
            not allows_zero, _sequence_to_alternatives(body, child_flags), unbounded
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
