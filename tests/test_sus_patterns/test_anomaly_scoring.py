import pytest

from guard_core.models import SecurityConfig


def test_threshold_field_default_and_bounds():
    assert SecurityConfig().detection_threat_score_threshold == 1.0
    assert SecurityConfig(detection_threat_score_threshold=2.5).detection_threat_score_threshold == 2.5
    with pytest.raises(Exception):
        SecurityConfig(detection_threat_score_threshold=-1.0)
