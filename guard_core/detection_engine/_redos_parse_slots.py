from __future__ import annotations

import importlib
import re
from collections.abc import Callable
from typing import Any, NamedTuple

from guard_core.detection_engine._redos_ignorecase_fold import expand_ignorecase
from guard_core.detection_engine._redos_intervals import (
    _IntervalSet,
    cached_category_intervals,
)


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


class _PairingAtom(NamedTuple):
    intervals: _IntervalSet
    allows_zero: bool
    unbounded: bool
    predicate: Callable[[int], bool] | None = None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _PairingAtom):
            return NotImplemented
        return (self.intervals, self.allows_zero, self.unbounded) == (
            other.intervals,
            other.allows_zero,
            other.unbounded,
        )

    def __hash__(self) -> int:
        return hash((self.intervals, self.allows_zero, self.unbounded))


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


def _class_node_cache_key(op: Any, av: Any, flags: int) -> tuple[Any, Any, int]:
    if op is _regex_parser.IN:
        return (op, tuple(av), flags)
    return (op, av, flags)


def _compiled_node_predicate(compiled: Any) -> Callable[[int], bool]:
    def predicate(code_point: int) -> bool:
        return compiled.fullmatch(chr(code_point)) is not None

    return predicate


_CLASS_NODE_PREDICATE_CACHE: dict[tuple[Any, Any, int], Callable[[int], bool]] = {}


def _class_node_predicate(op: Any, av: Any, flags: int) -> Callable[[int], bool]:
    key = _class_node_cache_key(op, av, flags)
    cached = _CLASS_NODE_PREDICATE_CACHE.get(key)
    if cached is not None:
        return cached
    if op is _regex_parser.CATEGORY:
        predicate = _category_predicate(av, flags)
    else:
        predicate = _compiled_node_predicate(_compile_class_node(op, av, flags))
    _CLASS_NODE_PREDICATE_CACHE[key] = predicate
    return predicate


def _category_intervals(category: Any, flags: int) -> _IntervalSet:
    predicate = _category_predicate(category, flags)
    return cached_category_intervals((category, flags & re.ASCII), predicate)


def _apply_ignorecase(intervals: _IntervalSet, flags: int) -> _IntervalSet:
    if not flags & re.IGNORECASE:
        return intervals
    return expand_ignorecase(intervals, ascii_only=bool(flags & re.ASCII))


def _member_intervals(op: Any, av: Any, flags: int) -> _IntervalSet:
    if op is _regex_parser.CATEGORY:
        return _category_intervals(av, flags)
    if op is _regex_parser.RANGE:
        low, high = av
        return _apply_ignorecase(_IntervalSet.from_range(low, high), flags)
    if op is _regex_parser.LITERAL:
        return _apply_ignorecase(_IntervalSet.single(av), flags)
    return _IntervalSet.empty()


def _in_intervals(av: Any, flags: int) -> _IntervalSet:
    negate = False
    member = _IntervalSet.empty()
    for item_op, item_av in av:
        if item_op is _regex_parser.NEGATE:
            negate = True
            continue
        member = member.union(_member_intervals(item_op, item_av, flags))
    return member.complement() if negate else member


def _any_intervals(flags: int) -> _IntervalSet:
    if flags & re.DOTALL:
        return _IntervalSet.full()
    return _IntervalSet.full().difference(_IntervalSet.single(ord("\n")))


def _node_intervals(op: Any, av: Any, flags: int) -> _IntervalSet:
    if op is _regex_parser.NOT_LITERAL:
        return _apply_ignorecase(_IntervalSet.single(av), flags).complement()
    if op is _regex_parser.IN:
        return _in_intervals(av, flags)
    if op is _regex_parser.ANY:
        return _any_intervals(flags)
    return _member_intervals(op, av, flags)


def _candidate_chars_for_atom_text(atom_text: str, flags: int) -> frozenset[str]:
    try:
        parsed = _regex_parser.parse(atom_text, flags)
    except re.error:
        return frozenset()
    if len(parsed.data) != 1:
        return frozenset()
    op, av = parsed.data[0]
    intervals = _node_intervals(op, av, parsed.state.flags)
    return frozenset(chr(cp) for cp in intervals.component_first_members())


def _pairing_atom(
    op: Any, av: Any, flags: int, allows_zero: bool, unbounded: bool
) -> _PairingAtom:
    intervals = _node_intervals(op, av, flags)
    predicate = _class_node_predicate(op, av, flags)
    return _PairingAtom(intervals, allows_zero, unbounded, predicate)


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
