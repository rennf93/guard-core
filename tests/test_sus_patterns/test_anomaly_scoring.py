import pytest

from guard_core.models import SecurityConfig
from guard_core.handlers.suspatterns_handler import (
    DETECTION_CATEGORY_WEIGHTS,
    _resolve_pattern_weight,
)


def test_threshold_field_default_and_bounds():
    assert SecurityConfig().detection_threat_score_threshold == 1.0
    assert SecurityConfig(detection_threat_score_threshold=2.5).detection_threat_score_threshold == 2.5
    with pytest.raises(Exception):
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
