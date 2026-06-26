import pytest
from pydantic import ValidationError

from guard_core.handlers.suspatterns_handler import (
    DETECTION_CATEGORY_WEIGHTS,
    SusPatternsManager,
    _resolve_pattern_weight,
)
from guard_core.models import SecurityConfig


def test_threshold_field_default_and_bounds():
    assert SecurityConfig().detection_threat_score_threshold == 1.0
    raised = SecurityConfig(detection_threat_score_threshold=2.5)
    assert raised.detection_threat_score_threshold == 2.5
    with pytest.raises(ValidationError):
        SecurityConfig(detection_threat_score_threshold=-1.0)


def test_resolve_weight_defaults_to_category_one():
    assert _resolve_pattern_weight(r"some-pattern", "sqli") == 1.0
    assert DETECTION_CATEGORY_WEIGHTS["sqli"] == 1.0


@pytest.mark.asyncio
async def test_regex_threat_dict_carries_weight(sus_patterns_manager_with_detection):
    result = await sus_patterns_manager_with_detection.detect(
        "<script>alert(1)</script>", "127.0.0.1", context="unknown"
    )
    regex_threats = [t for t in result["threats"] if t["type"] == "regex"]
    assert regex_threats
    assert all(t["weight"] == 1.0 for t in regex_threats)


@pytest.mark.asyncio
async def test_single_match_still_flagged_at_default_threshold(
    sus_patterns_manager_with_detection,
):
    result = await sus_patterns_manager_with_detection.detect(
        "<script>alert(1)</script>", "127.0.0.1", context="unknown"
    )
    assert result["is_threat"] is True
    assert result["threat_score"] == 1.0


@pytest.mark.asyncio
async def test_threshold_gate_suppresses_below_threshold():
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    config = SecurityConfig(detection_threat_score_threshold=2.0)
    manager = SusPatternsManager(config)
    try:
        result = await manager.detect(
            "<script>alert(1)</script>", "127.0.0.1", context="unknown"
        )
        assert result["is_threat"] is False
    finally:
        await manager.reset()
        SusPatternsManager._instance = None
        SusPatternsManager._config = None
