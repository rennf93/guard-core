import logging
import re
import time
from unittest.mock import MagicMock, patch

import pytest

from guard_core.sync.detection_engine._redos_class_intersection import (
    _class_intersection_fills,
    _quantified_atom_sequence,
)
from guard_core.sync.detection_engine._redos_cost_arbiter import (
    _PATTERN_SAFETY_DEFAULT_CAP,
    _REACH_PROBE_SIZES,
    _median,
    _reach_probe_cost_verdict,
    _reach_probe_unreachable_reason,
    _reach_probe_verdict_from_samples,
    _time_reach_probes_subprocess,
)
from guard_core.sync.detection_engine._redos_probe_fill import (
    _fill_to_length,
    _leading_literal_prefix,
    _reach_probe_candidate_builders,
    _repeat_probe_to_length,
)
from guard_core.sync.detection_engine.compiler import PatternCompiler

_EVENT_HANDLER_PATTERN = (
    r"(?:<[^<>]*(?<!=)(?<!=\")(?<!=')[\s/]+on\w+\s*="
    r"(?:[\"'][^\"']*[\"']|[^\s>]+))"
)


def test_quantified_atom_sequence_marks_boundaries_between_groups() -> None:
    sequence = _quantified_atom_sequence(r"[^<>]*(x)[\s/]+")
    assert sequence == ["[^<>]", None, None, "[\\s/]"]


def test_class_intersection_fills_finds_space_or_slash_for_event_handler() -> None:
    fills = _class_intersection_fills(_EVENT_HANDLER_PATTERN)
    assert fills
    assert all(c in " \t\n\r\x0b\x0c/" for c in fills)


def test_class_intersection_fills_ignores_disjoint_adjacent_classes() -> None:
    assert _class_intersection_fills(r"[a-c]+[x-z]+") == []


def test_class_intersection_fills_skips_pairs_across_alternation_boundary() -> None:
    assert _class_intersection_fills(r"[a-z]+|[a-z]+") == []


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
    assert _fill_to_length("ab", "x", 5) == "abxxx"
    assert _fill_to_length("abcdef", "x", 3) == "abc"


def test_reach_probe_candidate_builders_combines_all_strategies() -> None:
    builders = _reach_probe_candidate_builders(_EVENT_HANDLER_PATTERN)
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
        "guard_core.sync.detection_engine._redos_cost_arbiter.subprocess.run", _raise
    ):
        result = _time_reach_probes_subprocess("test", ["a"])
    assert result is None


def test_time_reach_probes_subprocess_returns_none_on_nonzero_returncode() -> None:
    fake_completed = MagicMock()
    fake_completed.returncode = 1
    fake_completed.stdout = ""

    with patch(
        "guard_core.sync.detection_engine._redos_cost_arbiter.subprocess.run",
        return_value=fake_completed,
    ):
        result = _time_reach_probes_subprocess("test", ["a"])
    assert result is None


def test_time_reach_probes_subprocess_returns_none_on_malformed_output() -> None:
    fake_completed = MagicMock()
    fake_completed.returncode = 0
    fake_completed.stdout = "not json"

    with patch(
        "guard_core.sync.detection_engine._redos_cost_arbiter.subprocess.run",
        return_value=fake_completed,
    ):
        result = _time_reach_probes_subprocess("test", ["a"])
    assert result is None


def test_time_reach_probes_subprocess_returns_none_on_compile_error() -> None:
    result = _time_reach_probes_subprocess("[invalid", ["a"])
    assert result is None


def test_time_reach_probes_subprocess_returns_sorted_samples_per_probe() -> None:
    result = _time_reach_probes_subprocess("abc", ["abc", "abcabc"])
    assert result is not None
    assert len(result) == 2
    for samples in result:
        assert len(samples) == 5
        assert samples == sorted(samples)


def test_reach_probe_cost_verdict_accepts_when_no_candidate_units_exist() -> None:
    is_safe, reason = _reach_probe_cost_verdict(r"[a-z]", None)
    assert is_safe is True
    assert reason == "Pattern appears safe"


def test_event_handler_rejects_under_intersection_fill_at_body_cap() -> None:
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(
        _EVENT_HANDLER_PATTERN, max_content_length=_PATTERN_SAFETY_DEFAULT_CAP
    )
    assert is_safe is False, (
        "event_handler must reject at the body cap under an intersection fill; "
        f"got safe={is_safe} ({reason})"
    )


def test_event_handler_intersection_fill_measures_super_linear_directly() -> None:
    fills = _class_intersection_fills(_EVENT_HANDLER_PATTERN)
    fill_char = fills[0]
    prefix = _leading_literal_prefix(_EVENT_HANDLER_PATTERN)
    probes = [_fill_to_length(prefix, fill_char, size) for size in _REACH_PROBE_SIZES]
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
        logger="guard_core.sync.detection_engine.compiler",
    ):
        is_safe, reason = _reach_probe_cost_verdict(pattern, None)
    assert is_safe is True
    assert reason == "Pattern appears safe"
    assert "structural rule flagged" in caplog.text
    assert "no repeatable adversarial trigger" in caplog.text
