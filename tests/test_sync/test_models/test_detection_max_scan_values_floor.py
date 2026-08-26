import pytest

from guard_core.models import SecurityConfig


def test_detection_max_scan_values_of_one_is_rejected() -> None:
    with pytest.raises(ValueError, match="greater than or equal to 2"):
        SecurityConfig(detection_max_scan_values=1)


def test_detection_max_scan_values_of_two_is_accepted() -> None:
    config = SecurityConfig(detection_max_scan_values=2)
    assert config.detection_max_scan_values == 2
