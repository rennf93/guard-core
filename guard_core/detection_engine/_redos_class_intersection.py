from guard_core.detection_engine._redos_ambiguous_tail import _atom_char_set
from guard_core.detection_engine._redos_structure import (
    _find_group_end,
    _skip_char_class,
)
from guard_core.detection_engine._redos_unreachable_terminator import (
    _skip_quantifier_at,
)

_BOUNDARY = None


def _class_atom_end(pattern: str, i: int) -> int | None:
    c = pattern[i]
    if c == "[":
        return _skip_char_class(pattern, i)
    if c == "\\" and i + 1 < len(pattern):
        return i + 2
    if c == ".":
        return i + 1
    return None


def _quantified_class_atom_at(pattern: str, i: int) -> tuple[str, int] | None:
    end = _class_atom_end(pattern, i)
    if end is None:
        return None
    qlen = _skip_quantifier_at(pattern, end)
    if qlen == 0:
        return None
    return pattern[i:end], end + qlen


def _group_open_step(pattern: str, i: int, n: int, atoms: list[str | None]) -> int:
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
    pattern: str, i: int, n: int, atoms: list[str | None]
) -> int:
    c = pattern[i]
    if c == "(":
        return _group_open_step(pattern, i, n, atoms)
    if c in ")|^$":
        atoms.append(_BOUNDARY)
        return i + 1
    atom = _quantified_class_atom_at(pattern, i)
    if atom is not None:
        atom_text, next_i = atom
        atoms.append(atom_text)
        return next_i
    skip = _skip_non_atom_token(pattern, i, n)
    return skip if skip is not None else i + 1


def _quantified_atom_sequence(pattern: str) -> list[str | None]:
    atoms: list[str | None] = []
    i = 0
    n = len(pattern)
    while i < n:
        i = _quantified_atom_sequence_step(pattern, i, n, atoms)
    return atoms


def _intersection_fill_for_pair(left: str | None, right: str | None) -> str | None:
    if left is _BOUNDARY or right is _BOUNDARY:
        return None
    assert left is not None and right is not None
    intersection = _atom_char_set(left) & _atom_char_set(right)
    return sorted(intersection)[0] if intersection else None


def _class_intersection_fills(pattern: str) -> list[str]:
    atoms = _quantified_atom_sequence(pattern)
    fills = [
        fill
        for left, right in zip(atoms, atoms[1:], strict=False)
        if (fill := _intersection_fill_for_pair(left, right)) is not None
    ]
    return fills
