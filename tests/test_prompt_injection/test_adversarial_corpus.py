"""Regression gate: every hand-crafted bypass in the corpus must still be caught.

The corpus is seeded empty in Phase 1 of the prompt-injection solidification
plan; Phase 2d populates it with one bypass per `pattern_id` in the default
library. Each bypass is a prompt that a human red-team crafted after reading
the pattern definition and trying to evade it — the pipeline's job is to
still return `is_malicious=True` via *some* layer, even when the original
pattern no longer matches.

When a new pattern lands, a matching bypass must be added to the corpus. When
the corpus is non-empty, each entry becomes a parametrised test case.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from guard_core.prompt_injection import PatternDetector
from guard_core.prompt_injection.scorer import InjectionScorer


def _repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").exists():
            return parent
    raise RuntimeError("repo root not found from test file location")


CORPUS_PATH = (
    _repo_root() / "tests" / "test_prompt_injection" / "adversarial_corpus.json"
)


def _load_bypasses() -> list[dict[str, str]]:
    data = json.loads(CORPUS_PATH.read_text())
    bypasses: list[dict[str, str]] = data.get("bypasses", [])
    return bypasses


@pytest.mark.parametrize(
    "entry",
    _load_bypasses(),
    ids=lambda e: f"{e.get('pattern_id', 'unknown')}__{e.get('name', 'bypass')}",
)
def test_bypass_is_still_caught(entry: dict[str, str]) -> None:
    """The full-stack pipeline must flag every corpus bypass as malicious.

    Pattern-only is allowed to miss (by definition — the entry IS a bypass
    of the named pattern). Some other layer in the full stack must catch it.
    """
    detector = PatternDetector(sensitivity=0.0)
    scorer = InjectionScorer(
        pattern_detector=detector,
        semantic_analyzer=None,
        detection_threshold=0.5,
        enable_statistical_boost=False,
    )
    text = entry["text"]
    assert scorer.is_malicious(text), (
        f"Bypass {entry.get('name', '?')} for pattern {entry.get('pattern_id', '?')}"
        f" passed through: {text[:100]!r}"
    )


def test_corpus_shape() -> None:
    """Corpus file is well-formed."""
    data = json.loads(CORPUS_PATH.read_text())
    assert isinstance(data, dict)
    assert "version" in data
    assert "bypasses" in data
    assert isinstance(data["bypasses"], list)
    for entry in data["bypasses"]:
        assert "pattern_id" in entry
        assert "text" in entry
        assert "name" in entry
