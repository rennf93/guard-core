from collections.abc import Iterator

from guard_core.detection_engine._redos_ambiguous_tail import _atom_char_set
from guard_core.detection_engine._redos_structure import (
    _find_group_end,
    _skip_char_class,
)
from guard_core.detection_engine._redos_unreachable_terminator import (
    _quantifier_at_allows_zero,
    _skip_quantifier_at,
)

_BOUNDARY = None

_QuantifiedAtom = tuple[str, bool]
_AtomSlot = _QuantifiedAtom | None


def _class_atom_end(pattern: str, i: int) -> int | None:
    c = pattern[i]
    if c == "[":
        return _skip_char_class(pattern, i)
    if c == "\\" and i + 1 < len(pattern):
        return i + 2
    if c == ".":
        return i + 1
    return None


def _quantified_class_atom_at(pattern: str, i: int) -> tuple[str, bool, int] | None:
    end = _class_atom_end(pattern, i)
    if end is None:
        return None
    qlen = _skip_quantifier_at(pattern, end)
    if qlen == 0:
        return None
    allows_zero = _quantifier_at_allows_zero(pattern, end)
    return pattern[i:end], allows_zero, end + qlen


def _group_open_step(pattern: str, i: int, n: int, atoms: list[_AtomSlot]) -> int:
    if pattern[i + 1 : i + 3] == "?:":
        return i + 3
    if i + 1 < n and pattern[i + 1] == "?":
        atoms.append(_BOUNDARY)
        end_paren = _find_group_end(pattern, i)
        return end_paren if end_paren is not None else i + 1
    atoms.append(_BOUNDARY)
    return i + 1


def _skip_non_atom_token(pattern: str, i: int, n: int) -> int | None:
    c = pattern[i]
    if c in "*+?":
        return i + 1
    if c == "{":
        end_brace = pattern.find("}", i)
        return end_brace + 1 if end_brace != -1 else i + 1
    if c == "\\" and i + 1 < n:
        return i + 2
    return None


def _quantified_atom_sequence_step(
    pattern: str, i: int, n: int, atoms: list[_AtomSlot]
) -> int:
    c = pattern[i]
    if c == "(":
        return _group_open_step(pattern, i, n, atoms)
    if c in ")|^$":
        atoms.append(_BOUNDARY)
        return i + 1
    atom = _quantified_class_atom_at(pattern, i)
    if atom is not None:
        atom_text, allows_zero, next_i = atom
        atoms.append((atom_text, allows_zero))
        return next_i
    skip = _skip_non_atom_token(pattern, i, n)
    return skip if skip is not None else i + 1


def _quantified_atom_sequence(pattern: str) -> list[_AtomSlot]:
    atoms: list[_AtomSlot] = []
    i = 0
    n = len(pattern)
    while i < n:
        i = _quantified_atom_sequence_step(pattern, i, n, atoms)
    return atoms


def _intersection_fill_for_pair(left: str, right: str) -> str | None:
    intersection = _atom_char_set(left) & _atom_char_set(right)
    return sorted(intersection)[0] if intersection else None


def _later_atoms_in_run(atoms: list[_AtomSlot], start: int) -> Iterator[str]:
    for j in range(start, len(atoms)):
        atom = atoms[j]
        if atom is _BOUNDARY:
            return
        text, allows_zero = atom
        yield text
        if not allows_zero:
            return


def _pair_fills_from_atom(atoms: list[_AtomSlot], i: int) -> list[str]:
    left = atoms[i]
    if left is _BOUNDARY:
        return []
    left_text, _left_allows_zero = left
    return [
        fill
        for right_text in _later_atoms_in_run(atoms, i + 1)
        if (fill := _intersection_fill_for_pair(left_text, right_text)) is not None
    ]


def _class_intersection_fills(pattern: str) -> list[str]:
    atoms = _quantified_atom_sequence(pattern)
    fills: list[str] = []
    for i in range(len(atoms)):
        fills.extend(_pair_fills_from_atom(atoms, i))
    return fills
