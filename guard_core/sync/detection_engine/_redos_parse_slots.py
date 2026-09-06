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


def _import_regex_compiler_module() -> Any:
    try:
        return importlib.import_module("re._compiler")
    except ImportError:
        return importlib.import_module("sre_compile")


_regex_parser: Any = _import_regex_parser_module()
_regex_compiler: Any = _import_regex_compiler_module()

_ALPHABET_EXTRA_CODE_POINTS: tuple[int, ...] = (
    0x100,
    0x400,
    0x4E00,
    0xFFFD,
    0x1F600,
    0xE000,
    0x10FFFF,
    0x1F601,
    0x131,
    0x17F,
    0x212A,
    0x3D1,
)
_ALPHABET: frozenset[str] = frozenset(chr(c) for c in range(256)) | frozenset(
    chr(c) for c in _ALPHABET_EXTRA_CODE_POINTS
)
_REQUIRED_CANDIDATE_CODE_POINTS: tuple[int, ...] = (
    0xE000,
    0x10FFFF,
    0x1F601,
    0x131,
    0x17F,
    0x212A,
    0x3D1,
)


class _PairingAtom(NamedTuple):
    charset: frozenset[str]
    allows_zero: bool
    unbounded: bool
    predicate: Callable[[int], bool] | None = None
    candidates: frozenset[int] = frozenset()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _PairingAtom):
            return NotImplemented
        return (self.charset, self.allows_zero, self.unbounded) == (
            other.charset,
            other.allows_zero,
            other.unbounded,
        )

    def __hash__(self) -> int:
        return hash((self.charset, self.allows_zero, self.unbounded))


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


def _compile_class_node(op: Any, av: Any, flags: int) -> Any:
    state = _regex_parser.State()
    state.flags = flags
    subpattern = _regex_parser.SubPattern(state, [(op, av)])
    return _regex_compiler.compile(subpattern, flags)


def _category_predicate(category: Any, flags: int) -> Callable[[int], bool]:
    escape = _CATEGORY_ESCAPES.get(category)
    if escape is None:
        return lambda code_point: True
    compiled = re.compile(escape, flags)
    return lambda code_point: compiled.fullmatch(chr(code_point)) is not None


def _category_charset(category: Any, flags: int) -> frozenset[str]:
    predicate = _category_predicate(category, flags)
    return frozenset(ch for ch in _ALPHABET if predicate(ord(ch)))


def _class_node_predicate(op: Any, av: Any, flags: int) -> Callable[[int], bool]:
    if op is _regex_parser.CATEGORY:
        return _category_predicate(av, flags)
    compiled = _compile_class_node(op, av, flags)
    return lambda code_point: compiled.fullmatch(chr(code_point)) is not None


def _pairing_charset(op: Any, av: Any, flags: int) -> frozenset[str]:
    predicate = _class_node_predicate(op, av, flags)
    return frozenset(ch for ch in _ALPHABET if predicate(ord(ch)))


def _clip_code_point(code_point: int) -> int:
    return max(0, min(0x10FFFF, code_point))


_RANGE_DENSE_WIDTH_CEILING = 256
_RANGE_SAMPLE_STRIDE = 64
_RANGE_BLOCK_SIZE = 256
_DENSE_CATEGORIES = frozenset(
    {_regex_parser.CATEGORY_DIGIT, _regex_parser.CATEGORY_SPACE}
)
_CATEGORY_MEMBER_CACHE: dict[tuple[Any, int], frozenset[int]] = {}


def _range_endpoints(low: int, high: int) -> set[int]:
    points = {low - 1, low, high, high + 1}
    width = high - low + 1
    if width <= _RANGE_DENSE_WIDTH_CEILING:
        points.update(range(low, high + 1))
        return points
    points.update(range(low, high + 1, _RANGE_SAMPLE_STRIDE))
    first_block = (low // _RANGE_BLOCK_SIZE) * _RANGE_BLOCK_SIZE
    points.update(
        block_start
        for block_start in range(first_block, high + 1, _RANGE_BLOCK_SIZE)
        if low <= block_start
    )
    return points


def _category_member_candidates(category: Any, flags: int) -> frozenset[int]:
    cache_key = (category, flags & re.ASCII)
    cached = _CATEGORY_MEMBER_CACHE.get(cache_key)
    if cached is not None:
        return cached
    predicate = _category_predicate(category, flags)
    members = frozenset(
        code_point for code_point in range(0x110000) if predicate(code_point)
    )
    _CATEGORY_MEMBER_CACHE[cache_key] = members
    return members


def _category_endpoints(category: Any, flags: int) -> set[int]:
    if category in _DENSE_CATEGORIES:
        return set(_category_member_candidates(category, flags))
    return set()


def _endpoints_for_class_item(op: Any, av: Any, flags: int) -> set[int]:
    if op is _regex_parser.LITERAL or op is _regex_parser.NOT_LITERAL:
        return {av - 1, av, av + 1}
    if op is _regex_parser.RANGE:
        low, high = av
        return _range_endpoints(low, high)
    if op is _regex_parser.CATEGORY:
        return _category_endpoints(av, flags)
    if op is _regex_parser.IN:
        points: set[int] = set()
        for item_op, item_av in av:
            if item_op is _regex_parser.NEGATE:
                continue
            points |= _endpoints_for_class_item(item_op, item_av, flags)
        return points
    return set()


def _candidate_code_points_for_node(op: Any, av: Any, flags: int) -> frozenset[int]:
    points = _endpoints_for_class_item(op, av, flags)
    points.update(_REQUIRED_CANDIDATE_CODE_POINTS)
    return frozenset(_clip_code_point(point) for point in points)


def _candidate_chars_for_atom_text(atom_text: str, flags: int) -> frozenset[str]:
    try:
        parsed = _regex_parser.parse(atom_text, flags)
    except re.error:
        return frozenset()
    if len(parsed.data) != 1:
        return frozenset()
    op, av = parsed.data[0]
    candidates = _candidate_code_points_for_node(op, av, parsed.state.flags)
    return frozenset(chr(code_point) for code_point in candidates)


def _pairing_atom(
    op: Any, av: Any, flags: int, allows_zero: bool, unbounded: bool
) -> _PairingAtom:
    predicate = _class_node_predicate(op, av, flags)
    charset = frozenset(ch for ch in _ALPHABET if predicate(ord(ch)))
    candidates = _candidate_code_points_for_node(op, av, flags)
    return _PairingAtom(charset, allows_zero, unbounded, predicate, candidates)


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
        return _pairing_atom(op, av, flags, False, False)
    return _nonpairing_slot(op, av, flags, False, False)


def _repeat_slot(av: tuple[int, int, list[Any]], flags: int) -> _Slot:
    low, high, body = av
    allows_zero = low == 0
    unbounded = high == _regex_parser.MAXREPEAT
    if len(body) == 1:
        op, item_av = body[0]
        if op in _PAIRING_OPS:
            return _pairing_atom(op, item_av, flags, allows_zero, unbounded)
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
