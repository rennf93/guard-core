from guard_core.detection_engine._redos_probe_fill import (
    _ambiguous_group_fill_builders,
    _ambiguous_group_fill_unit,
    _reach_probe_prefix_builders,
)
from guard_core.detection_engine._redos_reach_probe import _synthesize_reaching_probe
from guard_core.detection_engine._redos_stray_chooser import _build_stray_context


def test_reach_probe_prefix_builders_empty_when_reaching_probe_is_falsy() -> None:
    pattern = r"[^\x00-\U0010FFFF]+"
    assert _synthesize_reaching_probe(pattern) is None
    ctx = _build_stray_context(pattern, 0)
    assert _reach_probe_prefix_builders(pattern, ctx) == []


def test_ambiguous_group_fill_unit_none_when_inner_has_alternation() -> None:
    assert _ambiguous_group_fill_unit("a|b") is None


def test_ambiguous_group_fill_unit_none_when_atom_has_no_representative_char() -> None:
    assert _ambiguous_group_fill_unit(r"\1") is None


def test_ambiguous_group_fill_unit_returns_unit_when_atoms_have_chars() -> None:
    assert _ambiguous_group_fill_unit("a?") == "a"


def test_ambiguous_group_fill_builders_empty_when_group_nesting_too_deep() -> None:
    depth = 25
    pattern = "(" * depth + "a" + ")" * depth + "+"
    ctx = _build_stray_context(pattern, 0)
    assert _ambiguous_group_fill_builders(pattern, ctx) == []


def test_ambiguous_group_fill_builders_skips_ambiguous_inner_with_no_fill_unit() -> (
    None
):
    pattern = r"(\1{2,5})+"
    ctx = _build_stray_context(pattern, 0)
    assert _ambiguous_group_fill_builders(pattern, ctx) == []


def test_ambiguous_group_fill_builders_skips_non_ambiguous_inner() -> None:
    pattern = r"(abc)+"
    ctx = _build_stray_context(pattern, 0)
    assert _ambiguous_group_fill_builders(pattern, ctx) == []


def test_ambiguous_group_fill_builders_appends_when_unit_available() -> None:
    pattern = r"(a?)+"
    ctx = _build_stray_context(pattern, 0)
    builders = _ambiguous_group_fill_builders(pattern, ctx)
    assert len(builders) == 1
    assert builders[0](10).startswith("a")
