from pathlib import Path

import pytest

from tests.attack_simulation.harness import (
    fingerprint_corpus,
    run_benchmark,
    summarize_config,
)
from tests.attack_simulation.runner import build_detection_config

CORPUS = Path(__file__).parent / "corpus"


def test_summarize_config_extracts_detection_fields():
    summary = summarize_config(build_detection_config())
    assert summary["detection_compiler_timeout"] == 2.0
    assert summary["detection_semantic_threshold"] == 0.7


def test_fingerprint_is_stable():
    assert fingerprint_corpus(CORPUS) == fingerprint_corpus(CORPUS)


@pytest.mark.asyncio
async def test_run_benchmark_produces_report():
    report = await run_benchmark(CORPUS)
    assert 0.0 <= report["detection_rate"] <= 1.0
    assert 0.0 <= report["fp_rate"] <= 1.0
    assert report["totals"]["n_malicious"] > 0
    assert report["totals"]["n_benign"] > 0
    assert "config" in report and "corpus_fingerprint" in report
    assert "unmutated" in report["evasion_matrix"]
    assert all(0.0 <= rate <= 1.0 for rate in report["evasion_matrix"].values())
    assert report["per_class"]
