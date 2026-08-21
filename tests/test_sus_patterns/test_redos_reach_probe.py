from guard_core.detection_engine._redos_reach_probe import (
    _PROBE_REACH_STRESS_LEN,
    _reach_brace_quantifier_high,
    _reach_brace_quantifier_range,
    _reach_group_walk_target,
    _synth_char_class_atom,
    _synth_escape_atom,
    _synth_group_atom,
    _synthesize_reaching_probe,
    _synthesize_reaching_probe_segment,
)
from guard_core.detection_engine._redos_structure import _MAX_GROUP_NESTING_DEPTH


def test_reach_brace_quantifier_high_fixed_count() -> None:
    assert _reach_brace_quantifier_high(["3"]) == 3


def test_reach_brace_quantifier_high_unbounded() -> None:
    assert _reach_brace_quantifier_high(["2", ""]) == _PROBE_REACH_STRESS_LEN


def test_reach_brace_quantifier_high_bounded_range() -> None:
    assert _reach_brace_quantifier_high(["2", "5"]) == 5


def test_reach_brace_quantifier_high_rejects_non_digit_upper_bound() -> None:
    assert _reach_brace_quantifier_high(["2", "abc"]) is None


def test_reach_brace_quantifier_range_rejects_unterminated_brace() -> None:
    assert _reach_brace_quantifier_range("{2,", 0) is None


def test_reach_brace_quantifier_range_rejects_non_digit_lower_bound() -> None:
    assert _reach_brace_quantifier_range("{a,5}", 0) is None


def test_reach_brace_quantifier_range_rejects_non_digit_upper_bound() -> None:
    assert _reach_brace_quantifier_range("{2,abc}", 0) is None


def test_reach_group_walk_target_strips_named_group_prefix() -> None:
    assert _reach_group_walk_target("?P<n>xyz") == ("xyz", False)


def test_reach_group_walk_target_rejects_unterminated_named_group() -> None:
    assert _reach_group_walk_target("?P<n") == (None, False)


def test_reach_group_walk_target_skips_comment_group() -> None:
    assert _reach_group_walk_target("?#a comment") == (None, True)


def test_reach_group_walk_target_rejects_named_backreference() -> None:
    assert _reach_group_walk_target("?P=n") == (None, False)


def test_synth_escape_atom_rejects_trailing_lone_backslash() -> None:
    assert _synth_escape_atom("a\\", 1, set(), [100], {}) is None


def test_synth_escape_atom_rejects_unresolved_backreference() -> None:
    assert _synth_escape_atom(r"\1", 0, set(), [100], {}) is None


def test_synth_escape_atom_resolves_backreference_to_captured_group_text() -> None:
    assert _synth_escape_atom(r"\1", 0, set(), [100], {1: "ab"}) == ("ab", 2)


def test_synth_escape_atom_rejects_unrepresentable_escape() -> None:
    assert _synth_escape_atom(r"\p", 0, set(), [100], {}) is None


def test_synth_char_class_atom_rejects_unrepresentable_class() -> None:
    assert _synth_char_class_atom(r"[^\x00-\xff]", 0, set(), [100]) is None


def test_synth_group_atom_rejects_unterminated_group() -> None:
    assert _synth_group_atom("(abc", 0, set(), [100], 0, {}, [0]) is None


def test_synth_group_atom_rejects_unnormalizable_group() -> None:
    assert _synth_group_atom("(?P=n)", 0, set(), [100], 0, {}, [0]) is None


def test_synth_group_atom_propagates_nested_failure() -> None:
    assert _synth_group_atom(r"(?:\1)", 0, set(), [100], 0, {}, [0]) is None


def test_synth_group_atom_records_captured_group_text_by_number() -> None:
    group_texts: dict[int, str] = {}
    group_counter = [0]
    _synth_group_atom(r"(\d+)", 0, set(), [100], 0, group_texts, group_counter)
    assert group_texts.keys() == {1}
    assert set(group_texts[1]) == {"0"}
    assert len(group_texts[1]) > 0


def test_synth_group_atom_does_not_number_non_capturing_group() -> None:
    group_texts: dict[int, str] = {}
    group_counter = [0]
    _synth_group_atom(r"(?:a+)", 0, set(), [100], 0, group_texts, group_counter)
    assert group_texts == {}
    assert group_counter == [0]


def test_synthesize_reaching_probe_segment_fails_closed_past_depth_cap() -> None:
    body, ok = _synthesize_reaching_probe_segment(
        "x", set(), [100], _MAX_GROUP_NESTING_DEPTH + 1, {}, [0]
    )
    assert (body, ok) == ("", False)


def test_synthesize_reaching_probe_none_on_unrepresentable_construct() -> None:
    assert _synthesize_reaching_probe(r"\1") is None


def test_synthesize_reaching_probe_none_when_no_breaking_char_available() -> None:
    assert _synthesize_reaching_probe("\x01\x02\x03\x04\x05\x06\x07\x08") is None


def test_synthesize_reaching_probe_reaches_past_mandatory_literal_prefix() -> None:
    probe = _synthesize_reaching_probe(r"START#(?:[a-z]+[a-z]*)Z$")
    assert probe is not None
    assert probe.startswith("START#")


def test_synthesize_reaching_probe_repeats_captured_group_for_backreference() -> None:
    probe = _synthesize_reaching_probe(r"(a+)\1")
    assert probe is not None
    body = probe[:-1]
    half = len(body) // 2
    assert body[:half] == body[half:]


def test_synthesize_reaching_probe_resolves_backreference_by_group_number() -> None:
    probe = _synthesize_reaching_probe(r"(\d+)([a-z]+)\2")
    assert probe is not None
    body = probe[:-1]
    digits = len(body) - len(body.lstrip("0"))
    tail = body[digits:]
    assert set(tail) == {"a"}
    half = len(tail) // 2
    assert tail[:half] == tail[half:]
