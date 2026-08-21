import json
import logging
import math
import subprocess
import sys
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
_REACH_PROBE_BUDGET_SECONDS = 0.05
_REACH_PROBE_NOISE_FLOOR_SECONDS = 0.001
_REACH_PROBE_SAMPLE_COUNT = 5
_PATTERN_SAFETY_DEFAULT_CAP = 262144

_REACH_PROBE_TIMING_CHILD_SCRIPT = (
    "import json, re, sys, time\n"
    "pattern, probes, samples = json.loads(sys.stdin.read())\n"
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


def _time_reach_probes_subprocess(
    pattern: str, probes: list[str]
) -> list[list[float]] | None:
    payload = json.dumps([pattern, probes, _REACH_PROBE_SAMPLE_COUNT])
    try:
        completed = subprocess.run(
            [sys.executable, "-S", "-I", "-c", _REACH_PROBE_TIMING_CHILD_SCRIPT],
            input=payload,
            capture_output=True,
            text=True,
            timeout=_PATTERN_SAFETY_PROBE_TIMEOUT_SECONDS
            * len(probes)
            * _REACH_PROBE_SAMPLE_COUNT,
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


def _median(samples: list[float]) -> float:
    return samples[len(samples) // 2]


def _reach_probe_verdict_from_samples(
    samples_by_size: list[list[float]], cap: int
) -> tuple[bool, float, float, float, float]:
    medians = [_median(samples) for samples in samples_by_size]
    median_16, median_32 = medians[2], medians[3]
    min_32 = samples_by_size[3][0]
    ratio = (
        median_32 / median_16 if median_16 > _REACH_PROBE_NOISE_FLOOR_SECONDS else 1.0
    )
    doublings = math.log2(max(cap, 1) / _REACH_PROBE_SIZES[3])
    extrapolated = median_32 * (ratio**doublings) if ratio > 0 else median_32
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
    logger.warning(
        "guard_core pattern safety: structural rule flagged %r (%s) but %s; accepting",
        pattern,
        structural_violation,
        reason,
    )


def _first_over_budget_reason(
    pattern: str,
    builders: list[Callable[[int], str]],
    cap: int,
    structural_violation: str | None,
) -> str | None:
    for builder in builders:
        probes = [builder(size) for size in _REACH_PROBE_SIZES]
        samples_by_size = _time_reach_probes_subprocess(pattern, probes)
        if samples_by_size is None:
            return (
                structural_violation
                or "Pattern validation probe exceeded the killable-subprocess "
                "timeout while measuring reach-probe cost at scale"
            )
        over, extrapolated, ratio, min_32, median_32 = (
            _reach_probe_verdict_from_samples(samples_by_size, cap)
        )
        if over:
            return _reach_probe_cost_reason(
                structural_violation, extrapolated, ratio, cap, min_32, median_32
            )
    return None


def _reach_probe_cost_verdict(
    pattern: str, max_content_length: int | None
) -> tuple[bool, str]:
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
        pattern, builders, cap, structural_violation
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
