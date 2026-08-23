import json
import subprocess
import sys
from pathlib import Path

import pytest

_PROBE = Path(__file__).parent / "_scan_window_cap_removal_timing_probe.py"

_MAX_CPU_TIME_AT_LARGEST_SIZE_SECONDS = 0.05
_DOUBLING_RATIO_CEILING = 3.0
_NOISE_FLOOR_SECONDS = 0.001

_EXPECTED_LABELS = {
    "ldap_null_byte_attr",
    "ldap_null_byte_decoded_attr",
    "quote_splice",
}


def _assert_doubling_stays_linear(times: list[float], label: str) -> None:
    for earlier, later in zip(times, times[1:], strict=False):
        if earlier < _NOISE_FLOOR_SECONDS:
            continue
        ratio = later / earlier
        assert ratio < _DOUBLING_RATIO_CEILING, (
            f"{label} CPU-time doubling ratio grew past linear expectations: "
            f"{ratio:.2f}x across {times}"
        )


@pytest.mark.redos_timing
def test_the_three_converted_patterns_stay_under_the_cpu_time_budget() -> None:
    result = subprocess.run(
        [sys.executable, str(_PROBE)],
        capture_output=True,
        text=True,
        timeout=90,
    )

    assert result.returncode == 0, (
        f"timing probe subprocess failed:\n{result.stdout}\n{result.stderr}"
    )

    measured = json.loads(result.stdout)
    assert set(measured) == _EXPECTED_LABELS

    for label, series in measured.items():
        min_times = series["min"]
        median_times = series["median"]
        assert median_times[-1] < _MAX_CPU_TIME_AT_LARGEST_SIZE_SECONDS, (
            f"{label} exceeded the 50ms CPU-time budget at the largest "
            f"adversarial fill (median of 5): {median_times[-1]:.4f}s"
        )
        _assert_doubling_stays_linear(min_times, label)
