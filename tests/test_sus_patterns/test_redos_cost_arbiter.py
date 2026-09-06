import itertools
import logging
import re
import signal
import time
from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guard_core.detection_engine._redos_ambiguous_tail import _atom_char_set
from guard_core.detection_engine._redos_class_intersection import (
    _ALPHABET,
    _ATOMIC_GROUP,
    _category_charset,
    _class_intersection_fills,
    _class_intersection_probe_units,
    _class_item_charset,
    _group_crossing_result,
    _NonPairingSlot,
    _pairing_charset,
    _pairing_units_from,
    _PairingAtom,
    _pattern_slots,
    _regex_parser,
    _stray_for_pair,
)
from guard_core.detection_engine._redos_cost_arbiter import (
    _LOAD_FACTOR_CEILING,
    _LOAD_FACTOR_FLOOR,
    _PATTERN_SAFETY_DEFAULT_CAP,
    _REACH_PROBE_COMBINED_TIMEOUT_SECONDS,
    _REACH_PROBE_LARGE_SAMPLE_SECONDS,
    _REACH_PROBE_SAMPLE_COUNT,
    _REACH_PROBE_SIZES,
    _REFERENCE_SCAN_SECONDS,
    ReachProbeTiming,
    _clipped_timeout,
    _first_over_budget_reason,
    _load_factor,
    _median,
    _parse_reach_probe_child_output,
    _reach_probe_cost_reason,
    _reach_probe_cost_verdict,
    _reach_probe_timing_strategy,
    _reach_probe_unreachable_reason,
    _reach_probe_verdict_from_samples,
    _remaining_budget,
    _time_reach_probes_ascending,
    _time_reach_probes_subprocess,
    _time_single_reach_probe_subprocess,
)
from guard_core.detection_engine._redos_probe_fill import (
    _fill_to_length,
    _leading_literal_prefix,
    _reach_probe_candidate_builders,
    _repeat_probe_to_length,
)
from guard_core.detection_engine.compiler import PatternCompiler
from guard_core.handlers._suspatterns_sources import _SQLI_COMMENT_TERMINATOR_RE

_EVENT_HANDLER_PATTERN = (
    r"(?:<[^<>]*(?<!=)(?<!=\")(?<!=')[\s/]+on\w+\s*="
    r"(?:[\"'][^\"']*[\"']|[^\s>]+))"
)

_NEAR_BUDGET_SQLI_BUILTIN_PATTERN = (
    r"(?i)(?:\/\*![0-9]*\s*(?:OR|AND|UNION|SELECT|INSERT|DELETE|DROP"
    r"|CONCAT|CHAR|UPDATE)\b)"
)
_NEAR_BUDGET_SQLI_BUILTIN_PROBE = "/*!" + "0" * 31997


def _far_deadline() -> float:
    return time.monotonic() + 30.0


def _timing(
    samples_by_size: list[list[float]], load_factor: float = 1.0
) -> ReachProbeTiming:
    return ReachProbeTiming(samples_by_size, load_factor)


def test_pattern_slots_marks_a_capturing_group_as_a_boundary_slot() -> None:
    slots = _pattern_slots(r"[^<>]*(x)[\s/]+", 0)
    not_lt_gt = frozenset(ch for ch in _ALPHABET if ch not in "<>")
    slash_or_space = frozenset(ch for ch in _ALPHABET if re.fullmatch(r"[\s/]", ch))
    assert slots == [
        _PairingAtom(not_lt_gt, allows_zero=True, unbounded=True),
        _NonPairingSlot(
            is_boundary=True,
            inner=[[_PairingAtom(frozenset("x"), allows_zero=False, unbounded=False)]],
        ),
        _PairingAtom(slash_or_space, allows_zero=False, unbounded=True),
    ]


def test_pattern_slots_returns_none_when_the_pattern_fails_to_parse() -> None:
    assert _pattern_slots(r"[unterminated", 0) is None
    assert _class_intersection_probe_units(r"[unterminated", 0) == []


def test_pattern_slots_treats_a_bare_negation_as_a_not_literal_pairing_atom() -> None:
    slots = _pattern_slots(r"[^a]", 0)
    assert slots == [
        _PairingAtom(_ALPHABET - frozenset("a"), allows_zero=False, unbounded=False)
    ]


def test_pattern_slots_widens_any_to_the_full_alphabet_under_dotall() -> None:
    dotall_slots = _pattern_slots(r"(?s).", 0)
    plain_slots = _pattern_slots(r".", 0)
    assert dotall_slots == [_PairingAtom(_ALPHABET, allows_zero=False, unbounded=False)]
    assert plain_slots == [
        _PairingAtom(_ALPHABET - frozenset("\n"), allows_zero=False, unbounded=False)
    ]


def test_pattern_slots_treats_a_backreference_as_a_hard_boundary() -> None:
    slots = _pattern_slots(r"(a)\1", 0)
    assert slots is not None
    assert slots[1] == _NonPairingSlot(is_boundary=True, inner=None)


def test_class_intersection_fills_crosses_a_multi_slot_transparent_group() -> None:
    fills = _class_intersection_fills(r"'\s*(?:\d*(?!y)(z))+\s*--", 0)
    assert fills == []


def test_class_intersection_fills_stops_crossing_at_a_nested_backreference() -> None:
    fills = _class_intersection_fills(r"'\s*(?:(\s)\1z)+\s*--", 0)
    assert fills == []


def test_category_charset_falls_back_to_full_alphabet_for_unmapped_category() -> None:
    assert _category_charset(object(), 0) == _ALPHABET


def test_class_item_charset_falls_back_to_the_full_alphabet_for_an_unknown_item() -> (
    None
):
    assert _class_item_charset(object(), None, 0) == _ALPHABET


def test_pairing_charset_falls_back_to_category_charset_for_a_bare_category_op() -> (
    None
):
    charset = _pairing_charset(_regex_parser.CATEGORY, _regex_parser.CATEGORY_DIGIT, 0)
    assert charset == frozenset(ch for ch in _ALPHABET if re.fullmatch(r"\d", ch))


def test_group_crossing_result_rejects_past_the_max_depth() -> None:
    atom = _PairingAtom(frozenset("a"), allows_zero=False, unbounded=False)
    alternatives: list[list[Any]] = [[atom]]
    assert _group_crossing_result(alternatives, frozenset("a"), 999) is None


def test_pairing_units_from_returns_empty_when_the_start_slot_is_not_pairing() -> None:
    slots: list[Any] = [_NonPairingSlot(is_boundary=True, inner=None)]
    assert _pairing_units_from(slots, 0) == []


@pytest.mark.skipif(
    _ATOMIC_GROUP is None,
    reason="atomic groups require re._parser (Python 3.11+)",
)
def test_pattern_slots_treats_an_atomic_group_as_a_group_slot() -> None:
    slots = _pattern_slots(r"(?>a)+", 0)
    assert slots == [
        _NonPairingSlot(
            is_boundary=True,
            inner=[[_PairingAtom(frozenset("a"), allows_zero=False, unbounded=False)]],
            unbounded=True,
        )
    ]


def test_class_intersection_fills_finds_space_or_slash_for_event_handler() -> None:
    fills = _class_intersection_fills(_EVENT_HANDLER_PATTERN, 0)
    assert fills
    assert all(c in " \t\n\r\x0b\x0c/" for c in fills)


def test_class_intersection_fills_ignores_disjoint_adjacent_classes() -> None:
    assert _class_intersection_fills(r"[a-c]+[x-z]+", 0) == []


def test_class_intersection_fills_skips_pairs_across_alternation_boundary() -> None:
    assert _class_intersection_fills(r"[a-z]+|[a-z]+", 0) == []


def test_class_intersection_fills_pairs_across_an_empty_capable_middle_atom() -> None:
    fills = _class_intersection_fills(r"'\s*[\);]*\s*--", 0)
    assert fills == [sorted(_atom_char_set(r"\s"))[0]]


def test_class_intersection_fills_does_not_pair_across_a_mandatory_middle_atom() -> (
    None
):
    assert _class_intersection_fills(r"\s*[\);]+\s*", 0) == []


def test_class_intersection_fills_pairs_across_a_zero_admitting_group_middle() -> None:
    assert _class_intersection_fills(r"'\s*(?:ab)*\s*--", 0) == [
        sorted(_atom_char_set(r"\s"))[0]
    ]


def test_class_intersection_fills_pairs_across_a_negative_lookahead_middle() -> None:
    assert _class_intersection_fills(r"'\s*(?!x)\s*--", 0) == [
        sorted(_atom_char_set(r"\s"))[0]
    ]


@pytest.mark.redos_timing
def test_pattern_compiler_rejects_zero_admitting_group_and_lookahead_middles() -> None:
    compiler = PatternCompiler()
    for pattern in (r"'\s*(?:ab)*\s*--", r"'\s*(?!x)\s*--"):
        is_safe, reason = compiler.validate_pattern_safety(pattern)
        assert is_safe is False, (
            f"expected {pattern!r} to be rejected once a zero-admitting group or "
            f"lookaround is crossed by the class-intersection walk, got safe="
            f"{is_safe} ({reason})"
        )


def test_class_intersection_fills_crosses_a_mandatory_group_of_overlapping_atoms() -> (
    None
):
    assert _class_intersection_fills(r"'\s*(\s+)\s*--", 0) == [
        sorted(_atom_char_set(r"\s"))[0]
    ]


def test_class_intersection_fills_crosses_group_with_one_crossable_alt() -> None:
    assert _class_intersection_fills(r"'\s*(?:\s+|,)\s*--", 0) == [
        sorted(_atom_char_set(r"\s"))[0]
    ]


def test_class_intersection_fills_emits_a_fill_for_an_unbounded_crossable_group() -> (
    None
):
    assert _class_intersection_fills(r"'\s*(?:\s+|,)+\s*--", 0)


def test_class_intersection_fills_skips_a_non_overlapping_mandatory_group() -> None:
    assert _class_intersection_fills(r"'\s*(?:AND|OR)\s*--", 0) == []


@pytest.mark.redos_timing
def test_pattern_compiler_rejects_mandatory_group_crossed_by_overlapping_atoms() -> (
    None
):
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(r"'\s*(?:\s+)\s*--")
    assert is_safe is False, (
        "expected the mandatory group '(?:\\s+)' to be crossed by the surrounding "
        f"\\s* pair, got safe={is_safe} ({reason})"
    )


def test_class_intersection_fills_emits_a_fill_for_a_multi_char_alternation_group() -> (
    None
):
    fills = _class_intersection_fills(r"^[c-w]*(?:[g-z][g-z]|[g-z][g-z][g-z])*$", 0)
    assert fills == ["g"]


def test_class_intersection_fills_skips_a_non_crossable_multi_char_alternation() -> (
    None
):
    assert (
        _class_intersection_fills(r"^[a-f]*(?:[g-z][g-z]|[g-z][g-z][g-z])*$", 0) == []
    )


@pytest.mark.redos_timing
def test_pattern_compiler_rejects_unbounded_multi_char_alternation_zero_admitting_group() -> (  # noqa: E501
    None
):
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(
        r"^[c-w]*(?:[g-z][g-z]|[g-z][g-z][g-z])*$"
    )
    assert is_safe is False, (
        "expected the unbounded multi-character alternation group to be "
        f"crossed by the surrounding [c-w]* atom, got safe={is_safe} ({reason})"
    )
    assert "cost" in reason.lower() or "timeout" in reason.lower(), (
        f"expected a cost-arbiter rejection reason, got {reason!r}"
    )


def test_class_item_charset_folds_literal_case_under_ignorecase() -> None:
    assert _class_item_charset(_regex_parser.LITERAL, ord("a"), 0) == frozenset("a")
    assert _class_item_charset(
        _regex_parser.LITERAL, ord("a"), re.IGNORECASE
    ) == frozenset("aA")


def test_pairing_charset_folds_not_literal_case_under_ignorecase() -> None:
    charset = _pairing_charset(_regex_parser.NOT_LITERAL, ord("a"), re.IGNORECASE)
    assert "a" not in charset
    assert "A" not in charset


def test_class_intersection_probe_units_finds_no_fill_for_disjoint_case_sensitive_pair() -> (  # noqa: E501
    None
):
    assert _class_intersection_probe_units(r"[a-z]*[A-Z]+", 0) == []


def test_class_intersection_probe_units_finds_a_fill_once_ignorecase_folds_the_pair() -> (  # noqa: E501
    None
):
    units = _class_intersection_probe_units(r"[a-z]*[A-Z]+", re.IGNORECASE)
    assert units
    fill, _stray = units[0]
    assert fill in "aA"


@pytest.mark.redos_timing
def test_pattern_compiler_rejects_case_disjoint_pair_only_under_ignorecase() -> None:
    compiler = PatternCompiler()
    pattern = r"^[a-z]*[A-Z]+X$"
    is_safe_no_fold, reason_no_fold = compiler.validate_pattern_safety(pattern, flags=0)
    assert is_safe_no_fold is True, (
        f"expected the case-disjoint pair to be safe without IGNORECASE, got "
        f"safe={is_safe_no_fold} ({reason_no_fold})"
    )
    is_safe_folded, reason_folded = compiler.validate_pattern_safety(
        pattern, flags=re.IGNORECASE | re.MULTILINE
    )
    assert is_safe_folded is False, (
        "expected the pair to become crossable once IGNORECASE folds both "
        f"classes to overlap, got safe={is_safe_folded} ({reason_folded})"
    )
    assert "cost" in reason_folded.lower() or "timeout" in reason_folded.lower(), (
        f"expected a cost-arbiter rejection reason, got {reason_folded!r}"
    )


def test_class_intersection_probe_units_finds_a_latin1_fill() -> None:
    units = _class_intersection_probe_units(r"[a\x80-\xff]*[b\x80-\xff]+", 0)
    assert units
    fill, _stray = units[0]
    assert ord(fill) >= 0x80


@pytest.mark.redos_timing
def test_pattern_compiler_rejects_latin1_only_overlap() -> None:
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(r"^[a\x80-\xff]*[b\x80-\xff]+$")
    assert is_safe is False, (
        "expected the Latin-1-only overlap between the two classes to be "
        f"caught once the alphabet extends past code point 127, got "
        f"safe={is_safe} ({reason})"
    )
    assert "cost" in reason.lower() or "timeout" in reason.lower(), (
        f"expected a cost-arbiter rejection reason, got {reason!r}"
    )


def _element_charset(element: str) -> frozenset[str]:
    return frozenset(ch for ch in _ALPHABET if re.fullmatch(element, ch))


def _element_allows_zero(element: str) -> bool:
    return re.fullmatch(element, "") is not None


def _element_unbounded(element: str, charset: frozenset[str]) -> bool:
    if not charset:
        return False
    sample = sorted(charset)[0]
    return bool(re.fullmatch(element, sample * 200)) and bool(
        re.fullmatch(element, sample * 201)
    )


def _charset_slot(element: str) -> tuple[Any, ...]:
    charset = _element_charset(element)
    return (
        "charset",
        charset,
        _element_allows_zero(element),
        _element_unbounded(element, charset),
    )


_GRAMMAR_LEFT_ATOMS = [r"\s*", r"[a-z ]+", r"[^<>]*", r"\w*"]
_GRAMMAR_RIGHT_ATOMS = [r"\s*", r"[ a-z]*", r"[^\"']+", r"\w+"]
_GRAMMAR_ZERO_ADMITTING_MIDDLES = [
    "",
    r"[\);]*",
    r"x?",
    r"[0-9]{0,3}",
    r"(?:ab)*",
    r"(?:aa|bb)*",
    r"(?!x)",
    r"\d*?",
]
_GRAMMAR_MANDATORY_MIDDLES = [
    r"[\);]+",
    r"x",
    r"\.",
    r"[0-9]{1,3}",
    r"(?:ab)+",
    r"-",
    r"(?:\s+)",
    r"(?:\s|,)",
    r"(?:AND|OR)",
]
_GRAMMAR_HAND_SPECIFIED_MIDDLES = frozenset(
    {r"(?:ab)*", r"(?:aa|bb)*", r"(?!x)", r"(?:ab)+", r"(?:AND|OR)"}
)

_GRAMMAR_LEFT_META = {a: _charset_slot(a) for a in _GRAMMAR_LEFT_ATOMS}
_GRAMMAR_RIGHT_META = {a: _charset_slot(a) for a in _GRAMMAR_RIGHT_ATOMS}
_GRAMMAR_MIDDLE_META = {
    mid: _charset_slot(mid)
    for mid in _GRAMMAR_ZERO_ADMITTING_MIDDLES + _GRAMMAR_MANDATORY_MIDDLES
    if mid not in _GRAMMAR_HAND_SPECIFIED_MIDDLES
}
_GRAMMAR_MIDDLE_META[r"(?:ab)*"] = ("transparent",)
_GRAMMAR_MIDDLE_META[r"(?!x)"] = ("transparent",)
_GRAMMAR_MIDDLE_META[r"(?:ab)+"] = (
    "boundary_group",
    [[(_element_charset("a"), False), (_element_charset("b"), False)]],
    True,
    True,
)
_GRAMMAR_MIDDLE_META[r"(?:AND|OR)"] = (
    "boundary_group",
    [
        [
            (_element_charset("A"), False),
            (_element_charset("N"), False),
            (_element_charset("D"), False),
        ],
        [(_element_charset("O"), False), (_element_charset("R"), False)],
    ],
    False,
    True,
)
_GRAMMAR_MIDDLE_META[r"(?:aa|bb)*"] = (
    "boundary_group",
    [
        [(_element_charset("a"), False), (_element_charset("a"), False)],
        [(_element_charset("b"), False), (_element_charset("b"), False)],
    ],
    True,
    False,
)


def _oracle_alternative_crossing(
    atoms: list[tuple[frozenset[str], bool]], shared: frozenset[str]
) -> frozenset[str] | None:
    local = shared
    for atom_charset, atom_allows_zero in atoms:
        if atom_allows_zero:
            continue
        overlap = atom_charset & local
        if not overlap:
            return None
        local = overlap
    return local


def _oracle_group_crossing(
    alternatives: list[list[tuple[frozenset[str], bool]]], shared: frozenset[str]
) -> frozenset[str] | None:
    crossed = [
        result
        for alt in alternatives
        if (result := _oracle_alternative_crossing(alt, shared)) is not None
    ]
    if not crossed:
        return None
    return frozenset[str]().union(*crossed)


def _grammar_walk_hits_fill(
    charset: frozenset[str],
    allows_zero: bool,
    unbounded: bool,
    rest: list[tuple[Any, ...]],
) -> bool:
    if not unbounded:
        return False
    shared = charset
    for slot in rest:
        if slot[0] == "transparent":
            continue
        if slot[0] == "boundary_group":
            _, alternatives, group_unbounded, group_mandatory = slot
            crossing = _oracle_group_crossing(alternatives, shared)
            if crossing is None:
                if group_mandatory:
                    return False
                continue
            if group_unbounded:
                return True
            if group_mandatory:
                shared = crossing
            continue
        _, slot_charset, slot_allows_zero, slot_unbounded = slot
        overlap = slot_charset & shared
        if not overlap:
            if not slot_allows_zero:
                return False
            continue
        if slot_unbounded:
            return True
        if not slot_allows_zero:
            shared = overlap
    return False


def _grammar_expects_nonempty_fills(slots: list[tuple[Any, ...]]) -> bool:
    return any(
        _grammar_walk_hits_fill(slot[1], slot[2], slot[3], slots[i + 1 :])
        for i, slot in enumerate(slots)
        if slot[0] == "charset"
    )


def test_class_intersection_fills_matches_char_set_expectation_across_grammar() -> None:
    combos = itertools.product(
        _GRAMMAR_LEFT_ATOMS,
        _GRAMMAR_RIGHT_ATOMS,
        _GRAMMAR_ZERO_ADMITTING_MIDDLES + _GRAMMAR_MANDATORY_MIDDLES,
        _GRAMMAR_ZERO_ADMITTING_MIDDLES + _GRAMMAR_MANDATORY_MIDDLES,
    )
    for left, right, mid1, mid2 in combos:
        pattern = left + mid1 + mid2 + right
        slots = [
            _GRAMMAR_LEFT_META[left],
            _GRAMMAR_MIDDLE_META[mid1],
            _GRAMMAR_MIDDLE_META[mid2],
            _GRAMMAR_RIGHT_META[right],
        ]
        expected = _grammar_expects_nonempty_fills(slots)
        fills = _class_intersection_fills(pattern, 0)
        assert bool(fills) == expected, (
            f"pattern={pattern!r} expected_nonempty={expected} fills={fills}"
        )


_GRAMMAR_TIMING_MIDDLES = [
    "",
    r"[\);]*",
    r"x?",
    r"(?:ab)*",
    r"(?!x)",
    r"[\);]+",
    r"(?:ab)+",
    r"(?:AND|OR)",
    r"(?:\s+)",
]
_TIMING_PROBE_ALARM_SECONDS = 1


class _TimingProbeTimedOut(Exception):
    pass


def _timing_probe_alarm_handler(*_signal_args: object) -> None:
    raise _TimingProbeTimedOut


def _min_process_time(compiled: re.Pattern, probe: str, samples: int = 3) -> float:
    best = float(_TIMING_PROBE_ALARM_SECONDS)
    previous_handler = signal.signal(signal.SIGALRM, _timing_probe_alarm_handler)
    try:
        for _ in range(samples):
            signal.alarm(_TIMING_PROBE_ALARM_SECONDS)
            try:
                start = time.process_time()
                compiled.search(probe)
                elapsed = time.process_time() - start
            except _TimingProbeTimedOut:
                elapsed = float(_TIMING_PROBE_ALARM_SECONDS)
            finally:
                signal.alarm(0)
            best = min(best, elapsed)
            if elapsed >= _TIMING_PROBE_ALARM_SECONDS:
                break
    finally:
        signal.signal(signal.SIGALRM, previous_handler)
    return best


def _growth_ratio(pattern: str, fill: str, stray: str) -> float:
    compiled = re.compile(pattern)
    t2000 = _min_process_time(compiled, "'" + fill * 2000 + stray)
    if t2000 >= _TIMING_PROBE_ALARM_SECONDS:
        return float("inf")
    if t2000 < 0.001:
        return 1.0
    t4000 = _min_process_time(compiled, "'" + fill * 4000 + stray)
    return t4000 / t2000


def _timing_ground_truth_candidates(left: str, mid: str, right: str) -> set[str]:
    chars: set[str] = set()
    for element in (left, mid, right):
        charset = _element_charset(element)
        if charset:
            chars.add(sorted(charset)[0])
    return chars


@pytest.mark.redos_timing
def test_class_intersection_probe_units_are_ground_truthed_against_real_timing() -> (
    None
):
    for left in _GRAMMAR_LEFT_ATOMS:
        for right in _GRAMMAR_RIGHT_ATOMS:
            for mid in _GRAMMAR_TIMING_MIDDLES:
                pattern = "'" + left + mid + right + "--"
                units = _class_intersection_probe_units(pattern, 0)
                found_fills = {fill for fill, _stray in units}
                left_charset = _element_charset(left)
                right_charset = _element_charset(right)
                default_stray = _stray_for_pair(left_charset, right_charset)
                for candidate in _timing_ground_truth_candidates(left, mid, right):
                    stray = "\x00" if candidate == " " else default_stray
                    ratio = _growth_ratio(pattern, candidate, stray)
                    if ratio >= 3.0:
                        assert units, (
                            f"pattern={pattern!r} fill={candidate!r} stray={stray!r} "
                            f"measured super-linear growth (ratio={ratio:.2f}x) but "
                            f"the module produced no unit at all: {found_fills}"
                        )
                if not units:
                    ratio = _growth_ratio(pattern, " ", "\x00")
                    assert ratio < 3.0, (
                        f"pattern={pattern!r} produced no class-intersection unit but "
                        f"the space/NUL probe measured super-linear growth "
                        f"(ratio={ratio:.2f}x); a quadratic escape without a unit"
                    )


def test_repeat_probe_to_length_forces_non_alignment_on_exact_multiples() -> None:
    result = _repeat_probe_to_length("ab", 10)
    assert len(result) == 10
    assert result[-1] == "\x00"


def test_repeat_probe_to_length_stays_pure_repetition_when_not_aligned() -> None:
    result = _repeat_probe_to_length("abc", 10)
    assert len(result) == 10
    assert "\x00" not in result


def test_repeat_probe_to_length_empty_unit_returns_unit() -> None:
    assert _repeat_probe_to_length("", 10) == ""


def test_leading_literal_prefix_unwraps_transparent_group() -> None:
    assert _leading_literal_prefix(r"(?:<[^<>]*)") == "<"


def test_leading_literal_prefix_handles_escaped_literal_run() -> None:
    assert _leading_literal_prefix(r"\.\.;[^/\\]*") == "..;"


def test_leading_literal_prefix_empty_when_pattern_opens_with_metachar() -> None:
    assert _leading_literal_prefix(r"[^<>]*x") == ""


def test_fill_to_length_pads_and_truncates() -> None:
    assert _fill_to_length("ab", "x", "!", 4) == "abx!"
    assert _fill_to_length("abcdef", "x", "!", 3) == "abc"


def test_fill_to_length_appends_the_stray_as_the_last_character() -> None:
    assert _fill_to_length("ab", "x", "!", 6) == "abxxx!"


def test_fill_to_length_does_not_force_a_stray_when_body_room_is_one_or_fewer() -> None:
    assert _fill_to_length("ab", "x", "!", 3) == "abx"
    assert _fill_to_length("ab", "x", "!", 2) == "ab"


def test_reach_probe_candidate_builders_combines_all_strategies() -> None:
    builders = _reach_probe_candidate_builders(
        _EVENT_HANDLER_PATTERN, re.IGNORECASE | re.MULTILINE
    )
    assert len(builders) >= 1
    for builder in builders:
        probe = builder(4000)
        assert len(probe) == 4000


def test_median_of_five_presorted_samples_is_the_middle_value() -> None:
    assert _median([0.1, 0.2, 0.3, 0.4, 0.5]) == 0.3
    assert _median([0.01, 0.01, 0.3, 9.0, 9.0]) == 0.3


def test_reach_probe_verdict_extrapolates_down_for_a_small_cap() -> None:
    linear_samples = [[0.001] * 5, [0.002] * 5, [0.004] * 5, [0.008] * 5]
    over, extrapolated, ratio, min_32, median_32 = _reach_probe_verdict_from_samples(
        linear_samples, 512
    )
    assert over is False
    assert ratio == 2.0
    assert extrapolated < 0.008
    assert min_32 == 0.008
    assert median_32 == 0.008


def test_reach_probe_verdict_rejects_when_extrapolated_cost_exceeds_budget() -> None:
    quadratic_samples = [[0.001] * 5, [0.004] * 5, [0.016] * 5, [0.064] * 5]
    over, extrapolated, ratio, _min_32, _median_32 = _reach_probe_verdict_from_samples(
        quadratic_samples, _PATTERN_SAFETY_DEFAULT_CAP
    )
    assert over is True
    assert ratio == 4.0
    assert extrapolated > 0.05


def test_reach_probe_verdict_clamps_a_noisy_non_monotonic_ratio_to_one() -> None:
    non_monotonic_samples = [[0.001] * 5, [0.002] * 5, [0.010] * 5, [0.006] * 5]
    over, extrapolated, ratio, min_32, median_32 = _reach_probe_verdict_from_samples(
        non_monotonic_samples, 512
    )
    assert ratio == 1.0
    assert over is False
    assert extrapolated == min_32
    assert min_32 == 0.006
    assert median_32 == 0.006


def test_reach_probe_verdict_treats_tiny_times_as_inconclusive_ratio() -> None:
    noisy_samples = [[0.0] * 5, [0.0] * 5, [0.0] * 5, [0.0002] * 5]
    over, _extrapolated, ratio, _min_32, _median_32 = _reach_probe_verdict_from_samples(
        noisy_samples, _PATTERN_SAFETY_DEFAULT_CAP
    )
    assert ratio == 1.0
    assert over is False


def test_time_reach_probes_subprocess_returns_none_on_crash() -> None:
    def _raise(*args: object, **kwargs: object) -> None:
        raise OSError("no forkable subprocess slot")

    with patch(
        "guard_core.detection_engine._redos_cost_arbiter.subprocess.run", _raise
    ):
        result = _time_reach_probes_subprocess("test", ["a"], _far_deadline())
    assert result is None


def test_time_reach_probes_subprocess_returns_none_on_nonzero_returncode() -> None:
    fake_completed = MagicMock()
    fake_completed.returncode = 1
    fake_completed.stdout = ""

    with patch(
        "guard_core.detection_engine._redos_cost_arbiter.subprocess.run",
        return_value=fake_completed,
    ):
        result = _time_reach_probes_subprocess("test", ["a"], _far_deadline())
    assert result is None


def test_time_reach_probes_subprocess_returns_none_on_malformed_output() -> None:
    fake_completed = MagicMock()
    fake_completed.returncode = 0
    fake_completed.stdout = "not json"

    with patch(
        "guard_core.detection_engine._redos_cost_arbiter.subprocess.run",
        return_value=fake_completed,
    ):
        result = _time_reach_probes_subprocess("test", ["a"], _far_deadline())
    assert result is None


def test_time_reach_probes_subprocess_returns_none_on_compile_error() -> None:
    result = _time_reach_probes_subprocess("[invalid", ["a"], _far_deadline())
    assert result is None


def test_time_reach_probes_subprocess_returns_none_when_budget_is_exhausted() -> None:
    def _fail_if_called(*args: object, **kwargs: object) -> None:
        raise AssertionError("subprocess.run must not run without remaining budget")

    with patch(
        "guard_core.detection_engine._redos_cost_arbiter.subprocess.run",
        _fail_if_called,
    ):
        result = _time_reach_probes_subprocess("test", ["a"], time.monotonic() - 1.0)
    assert result is None


def _repeat_builder(unit: str) -> Callable[[int], str]:
    return lambda size: unit * size


def test_time_reach_probes_subprocess_clips_timeout_to_remaining_budget() -> None:
    captured: dict[str, float] = {}

    def _fake_run(*args: object, **kwargs: Any) -> None:
        captured["timeout"] = kwargs["timeout"]
        raise OSError("stop before actually spawning")

    with patch(
        "guard_core.detection_engine._redos_cost_arbiter.subprocess.run", _fake_run
    ):
        result = _time_reach_probes_subprocess("test", ["a"], time.monotonic() + 3.0)
    assert result is None
    assert captured["timeout"] <= 3.0


def test_time_reach_probes_subprocess_returns_sorted_samples_per_probe() -> None:
    result = _time_reach_probes_subprocess("abc", ["abc", "abcabc"], _far_deadline())
    assert result is not None
    assert len(result.samples_by_size) == 2
    for samples in result.samples_by_size:
        assert len(samples) == 5
        assert samples == sorted(samples)
    assert _LOAD_FACTOR_FLOOR <= result.load_factor <= _LOAD_FACTOR_CEILING


def test_reach_probe_cost_verdict_accepts_when_no_candidate_units_exist() -> None:
    is_safe, reason = _reach_probe_cost_verdict(r"[a-z]", None)
    assert is_safe is True
    assert reason == "Pattern appears safe"


@pytest.mark.redos_timing
def test_event_handler_rejects_under_intersection_fill_at_body_cap() -> None:
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(
        _EVENT_HANDLER_PATTERN, max_content_length=_PATTERN_SAFETY_DEFAULT_CAP
    )
    assert is_safe is False, (
        "event_handler must reject at the body cap under an intersection fill; "
        f"got safe={is_safe} ({reason})"
    )


def _assert_event_handler_intersection_fill_is_super_linear() -> None:
    units = _class_intersection_probe_units(_EVENT_HANDLER_PATTERN, re.IGNORECASE)
    fill_char, stray = units[0]
    prefix = _leading_literal_prefix(_EVENT_HANDLER_PATTERN)
    probes = [
        _fill_to_length(prefix, fill_char, stray, size) for size in _REACH_PROBE_SIZES
    ]
    compiled = re.compile(_EVENT_HANDLER_PATTERN, re.IGNORECASE)
    times = []
    for probe in probes:
        start = time.process_time()
        compiled.search(probe)
        times.append(time.process_time() - start)
    assert times[2] > 0.0005, "measurement floor too close to noise to trust the ratio"
    ratio = times[3] / times[2]
    assert ratio >= 3.0, (
        f"expected super-linear growth from the {fill_char!r} intersection fill, "
        f"measured ratio={ratio:.2f}x, times={times}"
    )


@pytest.mark.redos_timing
def test_event_handler_intersection_fill_measures_super_linear_directly() -> None:
    try:
        _assert_event_handler_intersection_fill_is_super_linear()
    except AssertionError:
        _assert_event_handler_intersection_fill_is_super_linear()


def test_reach_probe_unreachable_reason_echoes_structural_violation() -> None:
    assert (
        _reach_probe_unreachable_reason("some structural reason")
        == "some structural reason"
    )


def test_probe_cost_verdict_logs_disagreement_without_candidate_builders(
    caplog: pytest.LogCaptureFixture,
) -> None:
    pattern = r"(\b|\W+)*"
    with caplog.at_level(
        logging.WARNING,
        logger="guard_core.detection_engine.compiler",
    ):
        is_safe, reason = _reach_probe_cost_verdict(pattern, None)
    assert is_safe is True
    assert reason == "Pattern appears safe"
    assert "structural rule flagged" in caplog.text
    assert "no repeatable adversarial trigger" in caplog.text


def test_first_over_budget_reason_returns_structural_violation_when_over_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    quadratic_samples = [[0.001] * 5, [0.004] * 5, [0.016] * 5, [0.064] * 5]

    def _fake_timing(
        pattern: str, probes: list[str], deadline: float, flags: int
    ) -> ReachProbeTiming:
        return _timing(quadratic_samples)

    builder_calls = [0]

    def _builder(size: int) -> str:
        builder_calls[0] += 1
        return "a" * size

    monkeypatch.setattr(
        "guard_core.detection_engine._redos_cost_arbiter._time_reach_probes_ascending",
        _fake_timing,
    )
    reason = _first_over_budget_reason(
        r"(\w+\s?)*$",
        [_builder],
        _PATTERN_SAFETY_DEFAULT_CAP,
        "ambiguous optional tail",
        _far_deadline(),
    )
    assert reason is not None
    assert reason == "ambiguous optional tail"
    assert builder_calls[0] == len(_REACH_PROBE_SIZES)


def test_first_over_budget_reason_rejects_when_timing_probe_times_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "guard_core.detection_engine._redos_cost_arbiter._time_reach_probes_subprocess",
        lambda _pattern, _probes, _deadline, _flags: None,
    )

    def _builder(size: int) -> str:
        return "a" * size

    reason = _first_over_budget_reason(
        r"(\w+)*$",
        [_builder],
        _PATTERN_SAFETY_DEFAULT_CAP,
        None,
        _far_deadline(),
    )
    assert reason is not None
    assert "killable-subprocess timeout" in reason


def test_first_over_budget_reason_recovers_when_over_budget_does_not_repeat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    over_samples = _timing([[0.001] * 5, [0.004] * 5, [0.016] * 5, [0.064] * 5])
    under_samples = _timing([[0.0001] * 5, [0.0002] * 5, [0.0004] * 5, [0.0008] * 5])
    calls = iter([over_samples, under_samples])
    monkeypatch.setattr(
        "guard_core.detection_engine._redos_cost_arbiter._time_reach_probes_subprocess",
        lambda _pattern, _probes, _deadline, _flags: next(calls),
    )

    def _builder(size: int) -> str:
        return "a" * size

    reason = _first_over_budget_reason(
        r"(\w+)*$",
        [_builder],
        _PATTERN_SAFETY_DEFAULT_CAP,
        None,
        _far_deadline(),
    )
    assert reason is None


def test_first_over_budget_reason_rejects_when_over_budget_confirmation_times_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    over_samples = _timing([[0.001] * 5, [0.004] * 5, [0.016] * 5, [0.064] * 5])
    calls = iter([over_samples, None])
    monkeypatch.setattr(
        "guard_core.detection_engine._redos_cost_arbiter._time_reach_probes_subprocess",
        lambda _pattern, _probes, _deadline, _flags: next(calls),
    )

    def _builder(size: int) -> str:
        return "a" * size

    reason = _first_over_budget_reason(
        r"(\w+)*$",
        [_builder],
        _PATTERN_SAFETY_DEFAULT_CAP,
        None,
        _far_deadline(),
    )
    assert reason is not None
    assert "extrapolated CPU cost" in reason


def test_first_over_budget_reason_returns_none_when_under_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    under_samples = _timing([[0.0001] * 5, [0.0002] * 5, [0.0004] * 5, [0.0008] * 5])
    monkeypatch.setattr(
        "guard_core.detection_engine._redos_cost_arbiter._time_reach_probes_subprocess",
        lambda _pattern, _probes, _deadline, _flags: under_samples,
    )

    def _builder(size: int) -> str:
        return "a" * size

    reason = _first_over_budget_reason(
        r"(\w+)*$",
        [_builder],
        _PATTERN_SAFETY_DEFAULT_CAP,
        None,
        _far_deadline(),
    )
    assert reason is None


def test_first_over_budget_reason_retries_at_most_once_per_builder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    over_samples = _timing([[0.001] * 5, [0.004] * 5, [0.016] * 5, [0.064] * 5])
    under_samples = _timing([[0.0001] * 5, [0.0002] * 5, [0.0004] * 5, [0.0008] * 5])
    calls: list[str] = []

    def _fake_timing(
        _pattern: str, _probes: list[str], _deadline: float, _flags: int
    ) -> ReachProbeTiming:
        calls.append(_pattern)
        return over_samples if len(calls) % 2 else under_samples

    monkeypatch.setattr(
        "guard_core.detection_engine._redos_cost_arbiter._time_reach_probes_subprocess",
        _fake_timing,
    )

    builders = [_repeat_builder(ch) for ch in ("a", "b", "c")]
    reason = _first_over_budget_reason(
        r"(\w+)*$", builders, _PATTERN_SAFETY_DEFAULT_CAP, None, _far_deadline()
    )
    assert reason is None
    assert len(calls) == 2 * len(builders)


def test_first_over_budget_reason_skips_retry_when_budget_is_exhausted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    over_samples = _timing([[0.001] * 5, [0.004] * 5, [0.016] * 5, [0.064] * 5])
    timing_calls: list[int] = []

    def _fake_timing(
        _pattern: str, _probes: list[str], _deadline: float, _flags: int
    ) -> ReachProbeTiming:
        timing_calls.append(1)
        time.sleep(0.05)
        return over_samples

    monkeypatch.setattr(
        "guard_core.detection_engine._redos_cost_arbiter._time_reach_probes_subprocess",
        _fake_timing,
    )

    def _builder(size: int) -> str:
        return "a" * size

    deadline = time.monotonic() + 0.02
    reason = _first_over_budget_reason(
        r"(\w+)*$", [_builder], _PATTERN_SAFETY_DEFAULT_CAP, None, deadline
    )
    assert reason is not None
    assert "extrapolated CPU cost" in reason
    assert len(timing_calls) == 1


def test_remaining_budget_is_deadline_minus_now() -> None:
    deadline = time.monotonic() + 5.0
    remaining = _remaining_budget(deadline)
    assert 0.0 < remaining <= 5.0


def test_clipped_timeout_returns_default_when_budget_is_ample() -> None:
    deadline = time.monotonic() + 100.0
    assert _clipped_timeout(2.0, deadline) == pytest.approx(2.0, abs=0.05)


def test_clipped_timeout_returns_remaining_when_budget_is_tight() -> None:
    deadline = time.monotonic() + 1.0
    clipped = _clipped_timeout(100.0, deadline)
    assert 0.0 < clipped <= 1.0


def test_reach_probe_cost_verdict_bounds_the_whole_phase_to_one_shared_deadline() -> (
    None
):
    seen_deadlines: list[float] = []

    def _fake_over_budget_reason(
        pattern: str,
        builders: list[object],
        cap: int,
        structural_violation: str | None,
        deadline: float,
        flags: int,
    ) -> str | None:
        seen_deadlines.append(deadline)
        return None

    with patch(
        "guard_core.detection_engine._redos_cost_arbiter._first_over_budget_reason",
        _fake_over_budget_reason,
    ):
        before = time.monotonic()
        is_safe, reason = _reach_probe_cost_verdict(r"[a-z]+[a-z]+$", None)
        after = time.monotonic()

    assert is_safe is True
    assert reason == "Pattern appears safe"
    assert len(seen_deadlines) == 1
    deadline = seen_deadlines[0]
    assert before + _REACH_PROBE_COMBINED_TIMEOUT_SECONDS <= deadline
    assert deadline <= after + _REACH_PROBE_COMBINED_TIMEOUT_SECONDS


@pytest.mark.redos_timing
def test_retry_confirmation_adds_bounded_child_cpu_time_for_a_safe_pattern() -> None:
    safe_pattern = r"benign-literal-run"
    probes = [_repeat_probe_to_length("a", size) for size in _REACH_PROBE_SIZES]

    totals = []
    for _ in range(5):
        baseline = _time_reach_probes_subprocess(safe_pattern, probes, _far_deadline())
        retry = _time_reach_probes_subprocess(safe_pattern, probes, _far_deadline())
        assert baseline is not None
        assert retry is not None
        child_cpu_seconds = sum(
            t for row in baseline.samples_by_size for t in row
        ) + sum(t for row in retry.samples_by_size for t in row)
        totals.append(child_cpu_seconds)

    min_child_cpu_seconds = min(totals)
    assert min_child_cpu_seconds < 1.0, (
        "one baseline plus one retry reach-probe measurement of a safe pattern "
        f"cost {min_child_cpu_seconds:.4f}s of child CPU time across "
        f"{2 * len(_REACH_PROBE_SIZES) * 5} regex searches, expected "
        "comfortably under the 1.0s bound"
    )


def test_reach_probe_timing_strategy_selects_ascending_for_a_structural_violation() -> (
    None
):
    assert _reach_probe_timing_strategy("ambiguous optional tail") is (
        _time_reach_probes_ascending
    )


def test_reach_probe_timing_strategy_selects_combined_when_not_flagged() -> None:
    assert _reach_probe_timing_strategy(None) is _time_reach_probes_subprocess


def test_time_single_reach_probe_subprocess_returns_none_on_crash() -> None:
    def _raise(*args: object, **kwargs: object) -> None:
        raise OSError("no forkable subprocess slot")

    with patch(
        "guard_core.detection_engine._redos_cost_arbiter.subprocess.run", _raise
    ):
        result = _time_single_reach_probe_subprocess("test", "a", _far_deadline())
    assert result is None


def test_time_single_reach_probe_subprocess_returns_none_on_nonzero_returncode() -> (
    None
):
    fake_completed = MagicMock()
    fake_completed.returncode = 1
    fake_completed.stdout = ""

    with patch(
        "guard_core.detection_engine._redos_cost_arbiter.subprocess.run",
        return_value=fake_completed,
    ):
        result = _time_single_reach_probe_subprocess("test", "a", _far_deadline())
    assert result is None


def test_time_single_reach_probe_subprocess_returns_none_on_malformed_output() -> None:
    fake_completed = MagicMock()
    fake_completed.returncode = 0
    fake_completed.stdout = "not json"

    with patch(
        "guard_core.detection_engine._redos_cost_arbiter.subprocess.run",
        return_value=fake_completed,
    ):
        result = _time_single_reach_probe_subprocess("test", "a", _far_deadline())
    assert result is None


def test_time_single_reach_probe_subprocess_returns_none_on_compile_error() -> None:
    result = _time_single_reach_probe_subprocess("[invalid", "a", _far_deadline())
    assert result is None


def test_time_single_reach_probe_subprocess_returns_none_when_budget_is_exhausted() -> (
    None
):
    def _fail_if_called(*args: object, **kwargs: object) -> None:
        raise AssertionError("subprocess.run must not run without remaining budget")

    with patch(
        "guard_core.detection_engine._redos_cost_arbiter.subprocess.run",
        _fail_if_called,
    ):
        result = _time_single_reach_probe_subprocess(
            "test", "a", time.monotonic() - 1.0
        )
    assert result is None


def test_time_single_reach_probe_subprocess_returns_sorted_samples() -> None:
    result = _time_single_reach_probe_subprocess("abc", "abcabc", _far_deadline())
    assert result is not None
    (samples,) = result.samples_by_size
    assert len(samples) == 5
    assert samples == sorted(samples)


def test_time_reach_probes_ascending_returns_sorted_samples_per_probe() -> None:
    result = _time_reach_probes_ascending("abc", ["abc", "abcabc"], _far_deadline())
    assert result is not None
    assert len(result.samples_by_size) == 2
    for samples in result.samples_by_size:
        assert len(samples) == 5
        assert samples == sorted(samples)


def test_time_reach_probes_ascending_stops_at_the_first_failing_size() -> None:
    calls: list[str] = []

    def _fake_single(
        pattern: str, probe: str, deadline: float, flags: int
    ) -> ReachProbeTiming | None:
        calls.append(probe)
        return None if probe == "second" else _timing([[0.0] * 5])

    with patch(
        "guard_core.detection_engine._redos_cost_arbiter."
        "_time_single_reach_probe_subprocess",
        _fake_single,
    ):
        result = _time_reach_probes_ascending(
            "test", ["first", "second", "third"], _far_deadline()
        )

    assert result is None
    assert calls == ["first", "second"]


def test_time_reach_probes_ascending_keeps_the_smallest_load_factor() -> None:
    factors = iter([3.0, 2.0, 2.5])

    def _fake_single(
        pattern: str, probe: str, deadline: float, flags: int
    ) -> ReachProbeTiming:
        return _timing([[0.0] * 5], next(factors))

    with patch(
        "guard_core.detection_engine._redos_cost_arbiter."
        "_time_single_reach_probe_subprocess",
        _fake_single,
    ):
        result = _time_reach_probes_ascending("test", ["a", "b", "c"], _far_deadline())

    assert result is not None
    assert result.load_factor == 2.0
    assert len(result.samples_by_size) == 3


def test_load_factor_is_one_on_the_reference_host() -> None:
    assert _load_factor(_REFERENCE_SCAN_SECONDS) == 1.0


def test_load_factor_is_clamped_to_its_floor_and_ceiling() -> None:
    assert _load_factor(0.0) == _LOAD_FACTOR_FLOOR
    assert _load_factor(_REFERENCE_SCAN_SECONDS * 1000) == _LOAD_FACTOR_CEILING


def test_parse_reach_probe_child_output_requires_the_reference_scan() -> None:
    assert _parse_reach_probe_child_output('{"results": [[0.1]]}') is None
    assert _parse_reach_probe_child_output('{"error": "x", "reference": 0.002}') is None
    assert _parse_reach_probe_child_output("not json") is None


def test_parse_reach_probe_child_output_normalizes_by_the_reference_scan() -> None:
    timing = _parse_reach_probe_child_output(
        f'{{"results": [[0.3, 0.1, 0.2]], "reference": {_REFERENCE_SCAN_SECONDS * 2}}}'
    )
    assert timing is not None
    assert timing.samples_by_size == [[0.1, 0.2, 0.3]]
    assert timing.load_factor == pytest.approx(2.0)


def test_verdict_divides_measurements_by_the_load_factor() -> None:
    samples = [[0.008] * 5, [0.016] * 5]

    over_on_reference_host, extrapolated, _ratio, min_32, _median = (
        _reach_probe_verdict_from_samples(samples, _PATTERN_SAFETY_DEFAULT_CAP)
    )
    over_on_loaded_host, extrapolated_loaded, _ratio, min_32_loaded, _median = (
        _reach_probe_verdict_from_samples(samples, _PATTERN_SAFETY_DEFAULT_CAP, 4.0)
    )

    assert over_on_reference_host is True
    assert over_on_loaded_host is False
    assert min_32_loaded == pytest.approx(min_32 / 4.0)
    assert extrapolated_loaded == pytest.approx(extrapolated / 4.0)


def test_cost_reason_reports_the_load_factor() -> None:
    reason = _reach_probe_cost_reason(None, 0.2, 2.0, 262144, 0.025, 0.026, 2.5)
    assert "normalized by host load factor 2.50" in reason


def test_cost_reason_echoes_a_structural_violation_over_the_measurement() -> None:
    reason = _reach_probe_cost_reason("nested quantifier", 0.2, 2.0, 262144, 0.02, 0.02)
    assert reason == "nested quantifier"


def test_probe_child_keeps_every_sample_for_a_cheap_probe() -> None:
    timing = _time_reach_probes_subprocess("abc", ["abcabc"], _far_deadline())
    assert timing is not None
    assert [len(row) for row in timing.samples_by_size] == [_REACH_PROBE_SAMPLE_COUNT]


@pytest.mark.redos_timing
def test_probe_child_stops_sampling_once_a_sample_is_large() -> None:
    probes = [_repeat_probe_to_length("foo", size) for size in _REACH_PROBE_SIZES[-2:]]
    timing = _time_reach_probes_subprocess(r"(?:foo|bar)+$", probes, _far_deadline())
    assert timing is not None
    largest = timing.samples_by_size[-1]
    assert largest[0] > _REACH_PROBE_LARGE_SAMPLE_SECONDS
    assert len(largest) < _REACH_PROBE_SAMPLE_COUNT


@pytest.mark.redos_timing
def test_reference_scan_costs_the_same_as_a_near_budget_builtin_probe() -> None:
    timing = _time_reach_probes_subprocess(
        _NEAR_BUDGET_SQLI_BUILTIN_PATTERN,
        [_NEAR_BUDGET_SQLI_BUILTIN_PROBE],
        _far_deadline(),
    )
    assert timing is not None
    (samples,) = timing.samples_by_size
    min_32 = samples[0]
    reference_seconds = timing.load_factor * _REFERENCE_SCAN_SECONDS
    ratio = min_32 / reference_seconds
    assert 0.5 <= ratio <= 2.0, (
        "near-budget sqli builtin probe at 32000 chars measured min "
        f"{min_32:.4f}s against a child reference of {reference_seconds:.4f}s "
        f"(load factor {timing.load_factor:.2f}), ratio={ratio:.2f}x, "
        "expected the reference scan to track the probe within [0.5, 2.0]"
    )


@pytest.mark.redos_timing
def test_sqli_comment_terminator_pairing_rejects_old_and_accepts_new() -> None:
    compiler = PatternCompiler()
    is_safe_old, reason_old = compiler.validate_pattern_safety(r"'\s*[\);]*\s*--")
    assert is_safe_old is False, (
        "expected the pre-fix sqli comment terminator alternative to be rejected "
        "once cross-atom class-intersection pairing reaches it, got safe="
        f"{is_safe_old} ({reason_old})"
    )
    is_safe_new, reason_new = compiler.validate_pattern_safety(
        _SQLI_COMMENT_TERMINATOR_RE
    )
    assert is_safe_new is True, (
        f"expected the linear rewrite to pass pattern safety validation, "
        f"got safe={is_safe_new} ({reason_new})"
    )


def test_sqli_comment_terminator_rewrite_matches_the_previous_pattern() -> None:
    _PREVIOUS_QUADRATIC_SQLI_COMMENT_TERMINATOR = r"'\s*[\);]*\s*--|'[\);]*#(?:\n|\Z)"
    candidates = [
        "'--",
        "' --",
        "');--",
        "') ; --",
        "';  --",
        "'  )  --",
        "' ) ) --",
        "'x--",
        "'-- ",
        "' ; ; --",
        "''--",
        "' -",
        "')-",
    ]
    for candidate in candidates:
        old_no_match = (
            re.search(_PREVIOUS_QUADRATIC_SQLI_COMMENT_TERMINATOR, candidate) is None
        )
        new_no_match = re.search(_SQLI_COMMENT_TERMINATOR_RE, candidate) is None
        assert old_no_match == new_no_match, (
            f"terminator rewrite diverged for {candidate!r}: "
            f"old no-match={old_no_match}, new no-match={new_no_match}"
        )


@pytest.mark.redos_timing
def test_sqli_comment_terminator_rewrite_is_linear_on_a_quote_then_spaces() -> None:
    probe = "'" + " " * 31999
    compiled = re.compile(_SQLI_COMMENT_TERMINATOR_RE)
    times = []
    for _ in range(5):
        start = time.process_time()
        compiled.search(probe)
        times.append(time.process_time() - start)
    min_time = min(times)
    assert min_time < 0.01, (
        "expected the linear rewrite to search a 32000-char quote-then-spaces probe "
        f"in under 0.01s of min-of-5 CPU time, measured {min_time:.4f}s"
    )
