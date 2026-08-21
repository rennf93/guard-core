import functools
from collections.abc import Callable

from guard_core.sync.detection_engine._redos_ambiguous_tail import (
    _group_inner_is_ambiguous,
    _parse_flat_quantified_atoms_with_text,
    _representative_char_for_atom,
)
from guard_core.sync.detection_engine._redos_class_intersection import (
    _class_intersection_fills,
)
from guard_core.sync.detection_engine._redos_literal_runs import (
    _adversarial_literal_runs,
)
from guard_core.sync.detection_engine._redos_reach_probe import (
    _synthesize_reaching_probe,
)
from guard_core.sync.detection_engine._redos_structure import (
    GroupNestingTooDeep,
    _find_group_end,
    _iter_quantified_group_bodies,
)

_REACH_PROBE_PREFIX_CUT_LENGTHS = (20, 30, 50)
_REACH_PROBE_MAX_RUN_VARIANTS = 12
_REACH_PROBE_STRAY_BYTE = "\x00"
_LEADING_PREFIX_METACHARS = frozenset(".^$*+?{}[]()|\\")


def _repeat_probe_to_length(unit: str, length: int) -> str:
    if not unit:
        return unit
    reps = length // len(unit) + 1
    result = (unit * reps)[:length]
    homogeneous_unit = len(set(unit)) <= 1
    if homogeneous_unit or length % len(unit) == 0:
        result = result[:-1] + _REACH_PROBE_STRAY_BYTE
    return result


def _unwrap_leading_transparent_group(pattern: str) -> str:
    text = pattern
    while text.startswith("(?:"):
        end = _find_group_end(text, 0)
        if end is None or end != len(text):
            break
        text = text[3 : end - 1]
    return text


def _leading_literal_prefix(pattern: str) -> str:
    text = _unwrap_leading_transparent_group(pattern)
    prefix: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n and not text[i + 1].isalnum():
            prefix.append(text[i + 1])
            i += 2
            continue
        if c in _LEADING_PREFIX_METACHARS:
            break
        prefix.append(c)
        i += 1
    return "".join(prefix)


def _fill_to_length(prefix: str, fill_char: str, length: int) -> str:
    if length <= len(prefix):
        return prefix[:length]
    return prefix + fill_char * (length - len(prefix))


def _literal_run_builders(pattern: str) -> list[Callable[[int], str]]:
    runs = _adversarial_literal_runs(pattern)[:_REACH_PROBE_MAX_RUN_VARIANTS]
    return [functools.partial(_repeat_probe_to_length, run) for run in runs]


def _reach_probe_prefix_builders(pattern: str) -> list[Callable[[int], str]]:
    full_probe = _synthesize_reaching_probe(pattern)
    if not full_probe:
        return []
    body_only = full_probe[:-1].replace("?", "")
    builders: list[Callable[[int], str]] = []
    for cut in _REACH_PROBE_PREFIX_CUT_LENGTHS:
        prefix = body_only[:cut]
        if len(prefix) >= 2:
            builders.append(functools.partial(_repeat_probe_to_length, prefix))
    return builders


def _class_intersection_builders(pattern: str) -> list[Callable[[int], str]]:
    prefix = _leading_literal_prefix(pattern)
    return [
        functools.partial(_fill_to_length, prefix, fill_char)
        for fill_char in _class_intersection_fills(pattern)
    ]


def _ambiguous_group_fill_unit(inner: str) -> str | None:
    atoms = _parse_flat_quantified_atoms_with_text(inner)
    if atoms is None:
        return None
    chars = [_representative_char_for_atom(text) for text, _o, _u, _v in atoms]
    if any(char is None for char in chars):
        return None
    unit = "".join(char for char in chars if char is not None)
    return unit if unit else None


def _ambiguous_group_fill_builders(pattern: str) -> list[Callable[[int], str]]:
    builders: list[Callable[[int], str]] = []
    try:
        group_bodies = list(_iter_quantified_group_bodies(pattern))
    except GroupNestingTooDeep:
        return builders
    for _start, _end, inner in group_bodies:
        if not _group_inner_is_ambiguous(inner):
            continue
        unit = _ambiguous_group_fill_unit(inner)
        if unit is not None:
            builders.append(functools.partial(_repeat_probe_to_length, unit))
    return builders


def _reach_probe_candidate_builders(pattern: str) -> list[Callable[[int], str]]:
    return (
        _literal_run_builders(pattern)
        + _reach_probe_prefix_builders(pattern)
        + _class_intersection_builders(pattern)
        + _ambiguous_group_fill_builders(pattern)
    )
