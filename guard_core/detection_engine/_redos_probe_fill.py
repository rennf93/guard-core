import functools
from collections.abc import Callable

from guard_core.detection_engine._redos_ambiguous_tail import (
    _group_inner_is_ambiguous,
    _parse_flat_quantified_atoms_with_text,
    _representative_char_for_atom,
)
from guard_core.detection_engine._redos_class_intersection import (
    _class_intersection_probe_units,
)
from guard_core.detection_engine._redos_literal_runs import _adversarial_literal_runs
from guard_core.detection_engine._redos_reach_probe import _synthesize_reaching_probe
from guard_core.detection_engine._redos_stray_chooser import (
    _build_stray_context,
    _fill_to_length,
    _leading_literal_prefix,
    _repeat_probe_to_length,
    _StrayContext,
    choose_repeat_unit_stray,
)
from guard_core.detection_engine._redos_structure import (
    GroupNestingTooDeep,
    _iter_quantified_group_bodies,
)

_REACH_PROBE_PREFIX_CUT_LENGTHS = (20, 30, 50)
_REACH_PROBE_MAX_RUN_VARIANTS = 12


def _repeat_unit_builder(ctx: _StrayContext, unit: str) -> Callable[[int], str]:
    stray = choose_repeat_unit_stray(ctx, unit)
    return functools.partial(_repeat_probe_to_length, unit, stray=stray)


def _literal_run_builders(
    pattern: str, ctx: _StrayContext
) -> list[Callable[[int], str]]:
    runs = _adversarial_literal_runs(pattern)[:_REACH_PROBE_MAX_RUN_VARIANTS]
    return [_repeat_unit_builder(ctx, run) for run in runs]


def _reach_probe_prefix_builders(
    pattern: str, ctx: _StrayContext
) -> list[Callable[[int], str]]:
    full_probe = _synthesize_reaching_probe(pattern)
    if not full_probe:
        return []
    body_only = full_probe[:-1].replace("?", "")
    builders: list[Callable[[int], str]] = []
    for cut in _REACH_PROBE_PREFIX_CUT_LENGTHS:
        prefix = body_only[:cut]
        if len(prefix) >= 2:
            builders.append(_repeat_unit_builder(ctx, prefix))
    return builders


def _class_intersection_builders(
    pattern: str, flags: int
) -> list[Callable[[int], str]]:
    prefix = _leading_literal_prefix(pattern)
    return [
        functools.partial(_fill_to_length, prefix, fill_char, stray)
        for fill_char, stray in _class_intersection_probe_units(pattern, flags)
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


def _ambiguous_group_fill_builders(
    pattern: str, ctx: _StrayContext
) -> list[Callable[[int], str]]:
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
            builders.append(_repeat_unit_builder(ctx, unit))
    return builders


def _reach_probe_candidate_builders(
    pattern: str, flags: int
) -> list[Callable[[int], str]]:
    ctx = _build_stray_context(pattern, flags)
    return (
        _literal_run_builders(pattern, ctx)
        + _reach_probe_prefix_builders(pattern, ctx)
        + _class_intersection_builders(pattern, flags)
        + _ambiguous_group_fill_builders(pattern, ctx)
    )
