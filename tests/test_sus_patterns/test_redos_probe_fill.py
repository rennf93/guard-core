from guard_core.detection_engine._redos_probe_fill import (
    _ambiguous_group_fill_builders,
    _ambiguous_group_fill_unit,
    _leading_literal_prefix,
    _reach_probe_prefix_builders,
    _unwrap_leading_transparent_group,
)
from guard_core.detection_engine._redos_reach_probe import _synthesize_reaching_probe


def test_reach_probe_prefix_builders_empty_when_reaching_probe_is_falsy() -> None:
    assert _synthesize_reaching_probe(r"[\x01-\x08]+") is None
    assert _reach_probe_prefix_builders(r"[\x01-\x08]+") == []


def test_ambiguous_group_fill_unit_none_when_inner_has_alternation() -> None:
    assert _ambiguous_group_fill_unit("a|b") is None


def test_ambiguous_group_fill_unit_none_when_atom_has_no_representative_char() -> None:
    assert _ambiguous_group_fill_unit(r"\1") is None


def test_ambiguous_group_fill_unit_returns_unit_when_atoms_have_chars() -> None:
    assert _ambiguous_group_fill_unit("a?") == "a"


def test_ambiguous_group_fill_builders_empty_when_group_nesting_too_deep() -> None:
    depth = 25
    pattern = "(" * depth + "a" + ")" * depth + "+"
    assert _ambiguous_group_fill_builders(pattern) == []


def test_ambiguous_group_fill_builders_skips_ambiguous_inner_with_no_fill_unit() -> (
    None
):
    pattern = r"(\1{2,5})+"
    assert _ambiguous_group_fill_builders(pattern) == []


def test_ambiguous_group_fill_builders_skips_non_ambiguous_inner() -> None:
    assert _ambiguous_group_fill_builders(r"(abc)+") == []


def test_ambiguous_group_fill_builders_appends_when_unit_available() -> None:
    builders = _ambiguous_group_fill_builders(r"(a?)+")
    assert len(builders) == 1
    assert builders[0](10).startswith("a")


def test_unwrap_leading_transparent_group_breaks_when_group_not_at_end() -> None:
    assert _unwrap_leading_transparent_group(r"(?:abc)def") == "(?:abc)def"


def test_leading_literal_prefix_empty_when_unwrapped_text_is_empty() -> None:
    assert _leading_literal_prefix(r"(?:)") == ""
