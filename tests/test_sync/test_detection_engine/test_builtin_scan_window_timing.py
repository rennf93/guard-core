import json
import subprocess
import sys
from pathlib import Path

_PROBE = Path(__file__).parent / "_builtin_scan_window_timing_probe.py"

_DOUBLING_RATIO_CEILING = 3.5
_CEILING_AT_MAX_SIZE_SECONDS = 0.05


def _assert_doubling_stays_linear(pattern_label: str, times: list[float]) -> None:
    for earlier, later in zip(times, times[1:], strict=False):
        ratio = later / max(earlier, 1e-9)
        assert ratio < _DOUBLING_RATIO_CEILING, (
            f"{pattern_label[:60]!r} scan doubling ratio grew past linear "
            f"expectations: {ratio:.2f}x across {times}"
        )


def test_all_converted_builtin_patterns_scan_linearly_on_reach_probe_fill() -> None:
    result = subprocess.run(
        [sys.executable, str(_PROBE)],
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, (
        f"timing probe subprocess failed:\n{result.stdout}\n{result.stderr}"
    )

    measured: dict[str, list[float]] = json.loads(result.stdout)
    assert len(measured) == 11

    for source, times in measured.items():
        assert times[-1] < _CEILING_AT_MAX_SIZE_SECONDS, (
            f"{source[:60]!r} bounded scan at the largest adversarial fill "
            f"exceeded its ceiling: {times[-1]:.6f}s >= {_CEILING_AT_MAX_SIZE_SECONDS}s"
        )
        _assert_doubling_stays_linear(source, times)
