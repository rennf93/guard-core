import re
import string

from guard_core.detection_engine._redos_structure import (
    _NESTING_DEPTH_REJECTION_REASON,
    GroupNestingTooDeep,
    _iter_quantified_group_bodies,
    _skip_char_class,
)


def _parse_symbol_quantifier(inner: str, i: int) -> tuple[bool, bool, int]:
    symbol = inner[i]
    optional = symbol in "*?"
    unbounded = symbol in "*+"
    i += 1
    if i < len(inner) and inner[i] == "?":
        i += 1
    return optional, unbounded, i


def _parse_brace_quantifier(inner: str, i: int) -> tuple[bool, bool, int] | None:
    end_brace = inner.find("}", i)
    if end_brace == -1:
        return None
    parts = inner[i + 1 : end_brace].split(",")
    if not parts[0].isdigit():
        return None
    optional = int(parts[0]) == 0
    unbounded = len(parts) > 1 and parts[1] == ""
    i = end_brace + 1
    if i < len(inner) and inner[i] == "?":
        i += 1
    return optional, unbounded, i


def _parse_flat_quantified_atoms(inner: str) -> list[tuple[bool, bool]] | None:
    if "(" in inner or "|" in inner:
        return None
    atoms: list[tuple[bool, bool]] = []
    i = 0
    n = len(inner)
    while i < n:
        i += 1
        optional, unbounded = False, False
        if i < n and inner[i] in "*+?":
            optional, unbounded, i = _parse_symbol_quantifier(inner, i)
        elif i < n and inner[i] == "{":
            parsed = _parse_brace_quantifier(inner, i)
            if parsed is None:
                return None
            optional, unbounded, i = parsed
        atoms.append((optional, unbounded))
    return atoms


def _atoms_have_ambiguous_pair(atoms: list[tuple[bool, bool]]) -> bool:
    return any(
        atoms[a][1] and atoms[b][0] and a != b
        for a in range(len(atoms))
        for b in range(len(atoms))
    )


_OVERLAP_PROBE_ALPHABET = string.printable


def _compile_atom(atom_text: str) -> re.Pattern | None:
    try:
        return re.compile(atom_text, re.DOTALL)
    except re.error:
        return None


def _atom_char_set(atom_text: str) -> frozenset[str]:
    compiled = _compile_atom(atom_text)
    if compiled is None:
        return frozenset()
    return frozenset(ch for ch in _OVERLAP_PROBE_ALPHABET if compiled.fullmatch(ch))


def _atoms_overlap(text_a: str, text_b: str) -> bool:
    return not _atom_char_set(text_a).isdisjoint(_atom_char_set(text_b))


def _representative_char_for_atom(atom_text: str) -> str | None:
    compiled = _compile_atom(atom_text)
    if compiled is None:
        return None
    for ch in _OVERLAP_PROBE_ALPHABET:
        if compiled.fullmatch(ch):
            return ch
    return None


def _raw_atom_span(inner: str, i: int) -> int:
    if inner[i] == "\\" and i + 1 < len(inner):
        return i + 2
    if inner[i] == "[":
        return _skip_char_class(inner, i)
    return i + 1


def _parse_brace_quantifier_with_variability(
    inner: str, i: int
) -> tuple[bool, bool, bool, int] | None:
    end_brace = inner.find("}", i)
    if end_brace == -1:
        return None
    parts = inner[i + 1 : end_brace].split(",")
    if not parts[0].isdigit():
        return None
    optional = int(parts[0]) == 0
    unbounded = len(parts) > 1 and parts[1] == ""
    variable = unbounded or (len(parts) > 1 and parts[1] != parts[0])
    j = end_brace + 1
    if j < len(inner) and inner[j] == "?":
        j += 1
    return optional, unbounded, variable, j


def _parse_flat_quantified_atoms_with_text(
    inner: str,
) -> list[tuple[str, bool, bool, bool]] | None:
    atoms: list[tuple[str, bool, bool, bool]] = []
    i = 0
    n = len(inner)
    while i < n:
        if inner[i] == "(" or inner[i] == "|":
            return None
        atom_end = _raw_atom_span(inner, i)
        atom_text = inner[i:atom_end]
        i = atom_end
        optional, unbounded, variable = False, False, False
        if i < n and inner[i] in "*+?":
            optional, unbounded, i = _parse_symbol_quantifier(inner, i)
            variable = True
        elif i < n and inner[i] == "{":
            parsed = _parse_brace_quantifier_with_variability(inner, i)
            if parsed is None:
                return None
            optional, unbounded, variable, i = parsed
        atoms.append((atom_text, optional, unbounded, variable))
    return atoms


def _has_overlapping_cyclic_neighbor(atoms: list[tuple[str, bool, bool, bool]]) -> bool:
    n = len(atoms)
    for k, (text_k, _optional_k, _unbounded_k, variable_k) in enumerate(atoms):
        if not variable_k:
            continue
        next_text = atoms[(k + 1) % n][0]
        if _atoms_overlap(text_k, next_text):
            return True
    return False


def _group_inner_is_ambiguous(inner: str) -> bool:
    raw_atoms = _parse_flat_quantified_atoms_with_text(inner)
    if raw_atoms is None:
        return False
    if len(raw_atoms) == 1:
        _text, _optional, unbounded, variable = raw_atoms[0]
        return variable and not unbounded
    shape_only = [(optional, unbounded) for _text, optional, unbounded, _v in raw_atoms]
    if _atoms_have_ambiguous_pair(shape_only):
        return True
    return _has_overlapping_cyclic_neighbor(raw_atoms)


def _detect_ambiguous_optional_tail_in_quantified_group(pattern: str) -> str | None:
    try:
        for start, end, inner in _iter_quantified_group_bodies(pattern):
            if _group_inner_is_ambiguous(inner):
                return pattern[start:end]
    except GroupNestingTooDeep:
        return _NESTING_DEPTH_REJECTION_REASON
    return None


def _representative_char_and_end_for_escape_or_class(
    pattern: str, i: int
) -> tuple[int, str | None] | None:
    if pattern[i] == "\\" and i + 1 < len(pattern):
        atom_end = i + 2
        return atom_end, _representative_char_for_atom(pattern[i:atom_end])
    if pattern[i] == "[":
        atom_end = _skip_char_class(pattern, i)
        return atom_end, _representative_char_for_atom(pattern[i:atom_end])
    return None


def _extract_literal_chars(pattern: str) -> list[str]:
    chars: list[str] = []
    i = 0
    n = len(pattern)
    while i < n:
        result = _representative_char_and_end_for_escape_or_class(pattern, i)
        if result is not None:
            i, rep = result
            if rep is not None:
                chars.append(rep)
            continue
        c = pattern[i]
        if c.isalnum() or c in "_-./:@~ ":
            chars.append(c)
        i += 1
    return chars
