import json
import logging
import math
import re
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass

from guard_core.detection_engine._redos_probe_fill import (
    _reach_probe_candidate_builders,
)
from guard_core.detection_engine._redos_reach_probe import _synthesize_reaching_probe
from guard_core.detection_engine._redos_structural_prefilters import (
    _first_structural_safety_violation,
)

logger = logging.getLogger("guard_core.detection_engine.compiler")

_DEFAULT_PATTERN_FLAGS = re.IGNORECASE | re.MULTILINE

_PATTERN_SAFETY_PROBE_TIMEOUT_SECONDS = 2.0
_PATTERN_SAFETY_PROBE_PER_STRING_THRESHOLD_SECONDS = 0.05

_PATTERN_SAFETY_PROBE_CHILD_SCRIPT = (
    "import json, re, sys, time\n"
    "pattern, test_strings, threshold, flags = json.loads(sys.stdin.read())\n"
    "try:\n"
    "    compiled = re.compile(pattern, flags)\n"
    "except Exception as exc:\n"
    "    print(json.dumps({'safe': False, "
    "'reason': f'Pattern validation failed: {exc}'}))\n"
    "    raise SystemExit(0)\n"
    "for test_str in test_strings:\n"
    "    start = time.process_time()\n"
    "    compiled.search(test_str)\n"
    "    elapsed = time.process_time() - start\n"
    "    if elapsed > threshold:\n"
    "        reason = f'Pattern timed out on test string of length {len(test_str)}'\n"
    "        print(json.dumps({'safe': False, 'reason': reason}))\n"
    "        raise SystemExit(0)\n"
    "print(json.dumps({'safe': True, 'reason': 'Pattern appears safe'}))\n"
)


def _run_pattern_safety_probe_subprocess(
    pattern: str, test_strings: list[str], flags: int
) -> tuple[bool, str]:
    payload = json.dumps(
        [
            pattern,
            test_strings,
            _PATTERN_SAFETY_PROBE_PER_STRING_THRESHOLD_SECONDS,
            flags,
        ]
    )
    try:
        completed = subprocess.run(
            [sys.executable, "-S", "-I", "-c", _PATTERN_SAFETY_PROBE_CHILD_SCRIPT],
            input=payload,
            capture_output=True,
            text=True,
            timeout=_PATTERN_SAFETY_PROBE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return (
            False,
            "Pattern validation probe exceeded the "
            f"{_PATTERN_SAFETY_PROBE_TIMEOUT_SECONDS}s killable-subprocess timeout",
        )
    except Exception as e:
        return False, f"Pattern validation probe failed to run: {str(e)}"

    if completed.returncode != 0 or not completed.stdout.strip():
        return (
            False,
            f"Pattern validation probe failed: {completed.stderr.strip()[:200]}",
        )

    try:
        result = json.loads(completed.stdout.strip())
        return bool(result["safe"]), str(result["reason"])
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        return False, f"Pattern validation probe returned malformed output: {str(e)}"


_REACH_PROBE_SIZES = (4000, 8000, 16000, 32000)
_REACH_VERDICT_PROBE_SIZES = _REACH_PROBE_SIZES[-2:]
_REACH_PROBE_BUDGET_SECONDS = 0.05
_REFERENCE_SCAN_PATTERN = (
    r"(?i)/[0-9]*\s*(?:OR|AND|UNION|SELECT|INSERT|DELETE|DROP|CONCAT|CHAR|UPDATE)\b"
)
_REFERENCE_SCAN_PROBE_LENGTH = 32000
_REFERENCE_SCAN_SECONDS = 0.00229
_LOAD_FACTOR_FLOOR = 0.25
_LOAD_FACTOR_CEILING = 8.0
_REACH_PROBE_NOISE_FLOOR_SECONDS = 0.001
_REACH_PROBE_SAMPLE_COUNT = 5
_REACH_PROBE_LARGE_SAMPLE_SECONDS = 0.2
_PATTERN_SAFETY_DEFAULT_CAP = 262144

_REACH_PROBE_TIMING_CHILD_SCRIPT = (
    "import json, math, re, signal, sys, time\n"
    "pattern, probes, samples, deadline, flags = json.loads(sys.stdin.read())\n"
    "if hasattr(signal, 'alarm'):\n"
    "    signal.alarm(math.ceil(deadline))\n"
    "try:\n"
    "    compiled = re.compile(pattern, flags)\n"
    "except Exception as exc:\n"
    "    print(json.dumps({'error': str(exc)}))\n"
    "    raise SystemExit(0)\n"
    f"reference_compiled = re.compile({_REFERENCE_SCAN_PATTERN!r})\n"
    f"reference_probe = '/' + '0' * {_REFERENCE_SCAN_PROBE_LENGTH}\n"
    "reference_times = []\n"
    "for _ in range(samples):\n"
    "    start = time.process_time()\n"
    "    reference_compiled.search(reference_probe)\n"
    "    reference_times.append(time.process_time() - start)\n"
    "results = []\n"
    "for probe in probes:\n"
    "    probe_times = []\n"
    "    for _ in range(samples):\n"
    "        start = time.process_time()\n"
    "        compiled.search(probe)\n"
    "        probe_times.append(time.process_time() - start)\n"
    f"        if probe_times[-1] > {_REACH_PROBE_LARGE_SAMPLE_SECONDS}:\n"
    "            break\n"
    "    probe_times.sort()\n"
    "    results.append(probe_times)\n"
    "print(json.dumps({'results': results, 'reference': min(reference_times)}))\n"
)


@dataclass(frozen=True, slots=True)
class ReachProbeTiming:
    samples_by_size: list[list[float]]
    load_factor: float


def _load_factor(reference_seconds: float) -> float:
    raw = reference_seconds / _REFERENCE_SCAN_SECONDS
    return min(max(raw, _LOAD_FACTOR_FLOOR), _LOAD_FACTOR_CEILING)


def _parse_reach_probe_child_output(stdout: str) -> ReachProbeTiming | None:
    try:
        result = json.loads(stdout.strip())
    except json.JSONDecodeError:
        return None
    if "error" in result or "results" not in result or "reference" not in result:
        return None
    return ReachProbeTiming(
        [sorted(float(t) for t in row) for row in result["results"]],
        _load_factor(float(result["reference"])),
    )


_REACH_PROBE_CHILD_START_ALLOWANCE_SECONDS = 0.5
_REACH_PROBE_CHILD_TIMEOUT_SECONDS = (
    _PATTERN_SAFETY_PROBE_TIMEOUT_SECONDS + _REACH_PROBE_CHILD_START_ALLOWANCE_SECONDS
)
_REACH_PROBE_COMBINED_TIMEOUT_SECONDS = (
    _PATTERN_SAFETY_PROBE_TIMEOUT_SECONDS
    * len(_REACH_PROBE_SIZES)
    * _REACH_PROBE_SAMPLE_COUNT
)


def _remaining_budget(deadline: float) -> float:
    return deadline - time.monotonic()


def _clipped_timeout(default_timeout: float, deadline: float) -> float:
    return min(default_timeout, _remaining_budget(deadline))


def _run_reach_probe_child(
    pattern: str, probes: list[str], timeout: float, flags: int
) -> ReachProbeTiming | None:
    payload = json.dumps([pattern, probes, _REACH_PROBE_SAMPLE_COUNT, timeout, flags])
    try:
        completed = subprocess.run(
            [sys.executable, "-S", "-I", "-c", _REACH_PROBE_TIMING_CHILD_SCRIPT],
            input=payload,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except Exception:
        return None
    if completed.returncode != 0 or not completed.stdout.strip():
        return None
    return _parse_reach_probe_child_output(completed.stdout)


def _time_reach_probes_subprocess(
    pattern: str,
    probes: list[str],
    deadline: float,
    flags: int = _DEFAULT_PATTERN_FLAGS,
) -> ReachProbeTiming | None:
    timeout = _clipped_timeout(_REACH_PROBE_COMBINED_TIMEOUT_SECONDS, deadline)
    if timeout <= 0:
        return None
    return _run_reach_probe_child(pattern, probes, timeout, flags)


def _time_single_reach_probe_subprocess(
    pattern: str,
    probe: str,
    deadline: float,
    flags: int = _DEFAULT_PATTERN_FLAGS,
) -> ReachProbeTiming | None:
    timeout = _clipped_timeout(_REACH_PROBE_CHILD_TIMEOUT_SECONDS, deadline)
    if timeout <= 0:
        return None
    return _run_reach_probe_child(pattern, [probe], timeout, flags)


def _time_reach_probes_ascending(
    pattern: str,
    probes: list[str],
    deadline: float,
    flags: int = _DEFAULT_PATTERN_FLAGS,
) -> ReachProbeTiming | None:
    samples_by_size: list[list[float]] = []
    load_factor = _LOAD_FACTOR_CEILING
    for probe in probes:
        timing = _time_single_reach_probe_subprocess(pattern, probe, deadline, flags)
        if timing is None:
            return None
        samples_by_size.extend(timing.samples_by_size)
        load_factor = min(load_factor, timing.load_factor)
    return ReachProbeTiming(samples_by_size, load_factor)


def _median(samples: list[float]) -> float:
    return samples[len(samples) // 2]


def _reach_probe_verdict_from_samples(
    samples_by_size: list[list[float]], cap: int, load_factor: float = 1.0
) -> tuple[bool, float, float, float, float]:
    median_32 = _median(samples_by_size[-1]) / load_factor
    min_16 = samples_by_size[-2][0] / load_factor
    min_32 = samples_by_size[-1][0] / load_factor
    ratio = (
        max(min_32 / min_16, 1.0) if min_16 > _REACH_PROBE_NOISE_FLOOR_SECONDS else 1.0
    )
    doublings = math.log2(max(cap, 1) / _REACH_PROBE_SIZES[3])
    extrapolated = min_32 * (ratio**doublings) if ratio > 0 else min_32
    over_budget = extrapolated > _REACH_PROBE_BUDGET_SECONDS
    return over_budget, extrapolated, ratio, min_32, median_32


def _reach_probe_cost_reason(
    structural_violation: str | None,
    extrapolated: float,
    ratio: float,
    cap: int,
    min_32: float,
    median_32: float,
    load_factor: float = 1.0,
) -> str:
    if structural_violation is not None:
        return structural_violation
    return (
        f"Pattern extrapolated CPU cost at cap ({cap} chars) is {extrapolated:.3f}s, "
        f"exceeding the {_REACH_PROBE_BUDGET_SECONDS}s safety budget "
        f"(growth ratio {ratio:.2f}x per doubling, CPU time at 32000 chars: "
        f"min {min_32:.4f}s, median {median_32:.4f}s over "
        f"{_REACH_PROBE_SAMPLE_COUNT} runs, normalized by host load factor "
        f"{load_factor:.2f})"
    )


def _reach_probe_unreachable_reason(structural_violation: str | None) -> str:
    if structural_violation is not None:
        return structural_violation
    return (
        "Pattern validation probe could not construct a test string that "
        "reaches every quantified region of this pattern; rejecting rather "
        "than certifying safety on an unreachable probe"
    )


def _log_structural_disagreement(
    pattern: str, structural_violation: str, cap: int, reason: str
) -> None:
    from guard_core._utils.detection_scan import _redact_pattern_source

    logger.warning(
        "guard_core pattern safety: structural rule flagged %r (%s) but %s; accepting",
        _redact_pattern_source(pattern),
        structural_violation,
        reason,
    )


def _reach_probe_timing_strategy(
    structural_violation: str | None,
) -> Callable[[str, list[str], float, int], ReachProbeTiming | None]:
    if structural_violation is not None:
        return _time_reach_probes_ascending
    return _time_reach_probes_subprocess


def _reach_probe_sizes_for_strategy(
    structural_violation: str | None,
) -> tuple[int, ...]:
    if structural_violation is not None:
        return _REACH_PROBE_SIZES
    return _REACH_VERDICT_PROBE_SIZES


def _first_over_budget_reason(
    pattern: str,
    builders: list[Callable[[int], str]],
    cap: int,
    structural_violation: str | None,
    deadline: float,
    flags: int = _DEFAULT_PATTERN_FLAGS,
) -> str | None:
    time_probes = _reach_probe_timing_strategy(structural_violation)
    probe_sizes = _reach_probe_sizes_for_strategy(structural_violation)
    timed_probe_sets: set[tuple[str, ...]] = set()
    for builder in builders:
        probes = tuple(builder(size) for size in probe_sizes)
        if probes in timed_probe_sets:
            continue
        timed_probe_sets.add(probes)
        timing = time_probes(pattern, list(probes), deadline, flags)
        if timing is None:
            return (
                structural_violation
                or "Pattern validation probe exceeded the killable-subprocess "
                "timeout while measuring reach-probe cost at scale"
            )
        over, extrapolated, ratio, min_32, median_32 = (
            _reach_probe_verdict_from_samples(
                timing.samples_by_size, cap, timing.load_factor
            )
        )
        if over and _remaining_budget(deadline) > 0:
            retry = time_probes(pattern, list(probes), deadline, flags)
            if retry is not None:
                timing = retry
                over, extrapolated, ratio, min_32, median_32 = (
                    _reach_probe_verdict_from_samples(
                        timing.samples_by_size, cap, timing.load_factor
                    )
                )
        if over:
            return _reach_probe_cost_reason(
                structural_violation,
                extrapolated,
                ratio,
                cap,
                min_32,
                median_32,
                timing.load_factor,
            )
    return None


def _reach_probe_cost_verdict(
    pattern: str,
    max_content_length: int | None,
    flags: int = _DEFAULT_PATTERN_FLAGS,
) -> tuple[bool, str]:
    deadline = time.monotonic() + _REACH_PROBE_COMBINED_TIMEOUT_SECONDS
    cap = max_content_length if max_content_length else _PATTERN_SAFETY_DEFAULT_CAP
    structural_violation = _first_structural_safety_violation(pattern)
    if _synthesize_reaching_probe(pattern) is None:
        return False, _reach_probe_unreachable_reason(structural_violation)

    builders = _reach_probe_candidate_builders(pattern, flags)
    if not builders:
        if structural_violation is not None:
            _log_structural_disagreement(
                pattern,
                structural_violation,
                cap,
                "no repeatable adversarial trigger could be extracted to time",
            )
        return True, "Pattern appears safe"

    over_budget_reason = _first_over_budget_reason(
        pattern, builders, cap, structural_violation, deadline, flags
    )
    if over_budget_reason is not None:
        return False, over_budget_reason

    if structural_violation is not None:
        _log_structural_disagreement(
            pattern,
            structural_violation,
            cap,
            f"the timed reach-probe measured it under budget and linear at cap {cap}",
        )
    return True, "Pattern appears safe"
