import logging
import re
import time
from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guard_core.sync.detection_engine._redos_class_intersection import (
    _class_intersection_fills,
    _quantified_atom_sequence,
)
from guard_core.sync.detection_engine._redos_cost_arbiter import (
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


def _far_deadline() -> float:
    return time.monotonic() + 30.0


def _timing(
    samples_by_size: list[list[float]], load_factor: float = 1.0
) -> ReachProbeTiming:
    return ReachProbeTiming(samples_by_size, load_factor)


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
        "guard_core.sync.detection_engine._redos_cost_arbiter.subprocess.run", _raise
    ):
        result = _time_reach_probes_subprocess("test", ["a"], _far_deadline())
    assert result is None


def test_time_reach_probes_subprocess_returns_none_on_nonzero_returncode() -> None:
    fake_completed = MagicMock()
    fake_completed.returncode = 1
    fake_completed.stdout = ""

    with patch(
        "guard_core.sync.detection_engine._redos_cost_arbiter.subprocess.run",
        return_value=fake_completed,
    ):
        result = _time_reach_probes_subprocess("test", ["a"], _far_deadline())
    assert result is None


def test_time_reach_probes_subprocess_returns_none_on_malformed_output() -> None:
    fake_completed = MagicMock()
    fake_completed.returncode = 0
    fake_completed.stdout = "not json"

    with patch(
        "guard_core.sync.detection_engine._redos_cost_arbiter.subprocess.run",
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
        "guard_core.sync.detection_engine._redos_cost_arbiter.subprocess.run",
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
        "guard_core.sync.detection_engine._redos_cost_arbiter.subprocess.run", _fake_run
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
        logger="guard_core.sync.detection_engine.compiler",
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
        pattern: str, probes: list[str], deadline: float
    ) -> ReachProbeTiming:
        return _timing(quadratic_samples)

    builder_calls = [0]

    def _builder(size: int) -> str:
        builder_calls[0] += 1
        return "a" * size

    monkeypatch.setattr(
        "guard_core.sync.detection_engine._redos_cost_arbiter._time_reach_probes_ascending",
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
        "guard_core.sync.detection_engine._redos_cost_arbiter._time_reach_probes_subprocess",
        lambda _pattern, _probes, _deadline: None,
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
        "guard_core.sync.detection_engine._redos_cost_arbiter._time_reach_probes_subprocess",
        lambda _pattern, _probes, _deadline: next(calls),
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
        "guard_core.sync.detection_engine._redos_cost_arbiter._time_reach_probes_subprocess",
        lambda _pattern, _probes, _deadline: next(calls),
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
        "guard_core.sync.detection_engine._redos_cost_arbiter._time_reach_probes_subprocess",
        lambda _pattern, _probes, _deadline: under_samples,
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
        _pattern: str, _probes: list[str], _deadline: float
    ) -> ReachProbeTiming:
        calls.append(_pattern)
        return over_samples if len(calls) % 2 else under_samples

    monkeypatch.setattr(
        "guard_core.sync.detection_engine._redos_cost_arbiter._time_reach_probes_subprocess",
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
        _pattern: str, _probes: list[str], _deadline: float
    ) -> ReachProbeTiming:
        timing_calls.append(1)
        time.sleep(0.05)
        return over_samples

    monkeypatch.setattr(
        "guard_core.sync.detection_engine._redos_cost_arbiter._time_reach_probes_subprocess",
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
    ) -> str | None:
        seen_deadlines.append(deadline)
        return None

    with patch(
        "guard_core.sync.detection_engine._redos_cost_arbiter._first_over_budget_reason",
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
        "guard_core.sync.detection_engine._redos_cost_arbiter.subprocess.run", _raise
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
        "guard_core.sync.detection_engine._redos_cost_arbiter.subprocess.run",
        return_value=fake_completed,
    ):
        result = _time_single_reach_probe_subprocess("test", "a", _far_deadline())
    assert result is None


def test_time_single_reach_probe_subprocess_returns_none_on_malformed_output() -> None:
    fake_completed = MagicMock()
    fake_completed.returncode = 0
    fake_completed.stdout = "not json"

    with patch(
        "guard_core.sync.detection_engine._redos_cost_arbiter.subprocess.run",
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
        "guard_core.sync.detection_engine._redos_cost_arbiter.subprocess.run",
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
        pattern: str, probe: str, deadline: float
    ) -> ReachProbeTiming | None:
        calls.append(probe)
        return None if probe == "second" else _timing([[0.0] * 5])

    with patch(
        "guard_core.sync.detection_engine._redos_cost_arbiter."
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

    def _fake_single(pattern: str, probe: str, deadline: float) -> ReachProbeTiming:
        return _timing([[0.0] * 5], next(factors))

    with patch(
        "guard_core.sync.detection_engine._redos_cost_arbiter."
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
