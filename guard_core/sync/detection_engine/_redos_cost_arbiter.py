import json
import logging
import math
import subprocess
import sys
import time
from collections.abc import Callable

from guard_core.sync.detection_engine._redos_probe_fill import (
    _reach_probe_candidate_builders,
)
from guard_core.sync.detection_engine._redos_reach_probe import (
    _synthesize_reaching_probe,
)
from guard_core.sync.detection_engine._redos_structural_prefilters import (
    _first_structural_safety_violation,
)

logger = logging.getLogger("guard_core.sync.detection_engine.compiler")

_PATTERN_SAFETY_PROBE_TIMEOUT_SECONDS = 2.0
_PATTERN_SAFETY_PROBE_PER_STRING_THRESHOLD_SECONDS = 0.05

_PATTERN_SAFETY_PROBE_CHILD_SCRIPT = (
    "import json, re, sys, time\n"
    "pattern, test_strings, threshold = json.loads(sys.stdin.read())\n"
    "try:\n"
    "    compiled = re.compile(pattern)\n"
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
    pattern: str, test_strings: list[str]
) -> tuple[bool, str]:
    payload = json.dumps(
        [pattern, test_strings, _PATTERN_SAFETY_PROBE_PER_STRING_THRESHOLD_SECONDS]
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
_REACH_PROBE_NOISE_FLOOR_SECONDS = 0.001
_REACH_PROBE_SAMPLE_COUNT = 5
_PATTERN_SAFETY_DEFAULT_CAP = 262144

_REACH_PROBE_TIMING_CHILD_SCRIPT = (
    "import json, math, re, signal, sys, time\n"
    "pattern, probes, samples, deadline = json.loads(sys.stdin.read())\n"
    "if hasattr(signal, 'alarm'):\n"
    "    signal.alarm(math.ceil(deadline))\n"
    "try:\n"
    "    compiled = re.compile(pattern)\n"
    "except Exception as exc:\n"
    "    print(json.dumps({'error': str(exc)}))\n"
    "    raise SystemExit(0)\n"
    "results = []\n"
    "for probe in probes:\n"
    "    probe_times = []\n"
    "    for _ in range(samples):\n"
    "        start = time.process_time()\n"
    "        compiled.search(probe)\n"
    "        probe_times.append(time.process_time() - start)\n"
    "    probe_times.sort()\n"
    "    results.append(probe_times)\n"
    "print(json.dumps({'results': results}))\n"
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


def _time_reach_probes_subprocess(
    pattern: str, probes: list[str], deadline: float
) -> list[list[float]] | None:
    timeout = _clipped_timeout(_REACH_PROBE_COMBINED_TIMEOUT_SECONDS, deadline)
    if timeout <= 0:
        return None
    payload = json.dumps(
        [
            pattern,
            probes,
            _REACH_PROBE_SAMPLE_COUNT,
            timeout,
        ]
    )
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
    try:
        result = json.loads(completed.stdout.strip())
    except json.JSONDecodeError:
        return None
    if "error" in result or "results" not in result:
        return None
    return [sorted(float(t) for t in row) for row in result["results"]]


def _time_single_reach_probe_subprocess(
    pattern: str, probe: str, deadline: float
) -> list[float] | None:
    timeout = _clipped_timeout(_REACH_PROBE_CHILD_TIMEOUT_SECONDS, deadline)
    if timeout <= 0:
        return None
    payload = json.dumps(
        [
            pattern,
            [probe],
            _REACH_PROBE_SAMPLE_COUNT,
            timeout,
        ]
    )
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
    try:
        result = json.loads(completed.stdout.strip())
    except json.JSONDecodeError:
        return None
    if "error" in result or "results" not in result:
        return None
    return sorted(float(t) for t in result["results"][0])


def _time_reach_probes_ascending(
    pattern: str, probes: list[str], deadline: float
) -> list[list[float]] | None:
    samples_by_size = []
    for probe in probes:
        samples = _time_single_reach_probe_subprocess(pattern, probe, deadline)
        if samples is None:
            return None
        samples_by_size.append(samples)
    return samples_by_size


def _median(samples: list[float]) -> float:
    return samples[len(samples) // 2]


def _reach_probe_verdict_from_samples(
    samples_by_size: list[list[float]], cap: int
) -> tuple[bool, float, float, float, float]:
    median_32 = _median(samples_by_size[-1])
    min_16, min_32 = samples_by_size[-2][0], samples_by_size[-1][0]
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
) -> str:
    if structural_violation is not None:
        return structural_violation
    return (
        f"Pattern extrapolated CPU cost at cap ({cap} chars) is {extrapolated:.3f}s, "
        f"exceeding the {_REACH_PROBE_BUDGET_SECONDS}s safety budget "
        f"(growth ratio {ratio:.2f}x per doubling, CPU time at 32000 chars: "
        f"min {min_32:.4f}s, median {median_32:.4f}s over "
        f"{_REACH_PROBE_SAMPLE_COUNT} runs)"
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
    from guard_core.sync._utils.detection_scan import _redact_pattern_source

    logger.warning(
        "guard_core pattern safety: structural rule flagged %r (%s) but %s; accepting",
        _redact_pattern_source(pattern),
        structural_violation,
        reason,
    )


def _reach_probe_timing_strategy(
    structural_violation: str | None,
) -> Callable[[str, list[str], float], list[list[float]] | None]:
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
) -> str | None:
    time_probes = _reach_probe_timing_strategy(structural_violation)
    probe_sizes = _reach_probe_sizes_for_strategy(structural_violation)
    timed_probe_sets: set[tuple[str, ...]] = set()
    for builder in builders:
        probes = tuple(builder(size) for size in probe_sizes)
        if probes in timed_probe_sets:
            continue
        timed_probe_sets.add(probes)
        samples_by_size = time_probes(pattern, list(probes), deadline)
        if samples_by_size is None:
            return (
                structural_violation
                or "Pattern validation probe exceeded the killable-subprocess "
                "timeout while measuring reach-probe cost at scale"
            )
        over, extrapolated, ratio, min_32, median_32 = (
            _reach_probe_verdict_from_samples(samples_by_size, cap)
        )
        if over and _remaining_budget(deadline) > 0:
            retry = time_probes(pattern, list(probes), deadline)
            if retry is not None:
                over, extrapolated, ratio, min_32, median_32 = (
                    _reach_probe_verdict_from_samples(retry, cap)
                )
        if over:
            return _reach_probe_cost_reason(
                structural_violation, extrapolated, ratio, cap, min_32, median_32
            )
    return None


def _reach_probe_cost_verdict(
    pattern: str, max_content_length: int | None
) -> tuple[bool, str]:
    deadline = time.monotonic() + _REACH_PROBE_COMBINED_TIMEOUT_SECONDS
    cap = max_content_length if max_content_length else _PATTERN_SAFETY_DEFAULT_CAP
    structural_violation = _first_structural_safety_violation(pattern)
    if _synthesize_reaching_probe(pattern) is None:
        return False, _reach_probe_unreachable_reason(structural_violation)

    builders = _reach_probe_candidate_builders(pattern)
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
        pattern, builders, cap, structural_violation, deadline
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
