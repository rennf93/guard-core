import json
from pathlib import Path

import pytest

from tests.attack_simulation.harness import run_benchmark

_BASE = Path(__file__).parent
_TOLERANCE = 0.02


@pytest.mark.asyncio
async def test_detection_does_not_regress_against_baseline():
    baseline = json.loads((_BASE / "baseline.json").read_text())
    report = await run_benchmark(_BASE / "corpus")
    assert report["detection_rate"] >= baseline["detection_rate"] - _TOLERANCE
    assert report["fp_rate"] <= baseline["fp_rate"] + _TOLERANCE
