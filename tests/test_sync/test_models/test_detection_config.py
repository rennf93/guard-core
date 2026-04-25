import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.suspatterns_handler import ALL_DETECTION_CATEGORIES


def test_excluded_detection_headers_default_empty() -> None:
    config = SecurityConfig()
    assert config.excluded_detection_headers == set()


def test_excluded_detection_params_default_empty() -> None:
    config = SecurityConfig()
    assert config.excluded_detection_params == set()


def test_excluded_detection_body_fields_default_empty() -> None:
    config = SecurityConfig()
    assert config.excluded_detection_body_fields == set()


def test_excluded_fields_accept_sets() -> None:
    config = SecurityConfig(
        excluded_detection_headers={"authorization", "x-request-id"},
        excluded_detection_params={"csrf_token"},
        excluded_detection_body_fields={"password"},
    )
    assert config.excluded_detection_headers == {"authorization", "x-request-id"}
    assert config.excluded_detection_params == {"csrf_token"}
    assert config.excluded_detection_body_fields == {"password"}


def test_enabled_detection_categories_default_is_full_set() -> None:
    config = SecurityConfig()
    assert config.enabled_detection_categories == set(ALL_DETECTION_CATEGORIES)


def test_enabled_detection_categories_accepts_subset() -> None:
    config = SecurityConfig(enabled_detection_categories={"xss", "sqli"})
    assert config.enabled_detection_categories == {"xss", "sqli"}


def test_enabled_detection_categories_rejects_unknown_category() -> None:
    with pytest.raises(ValueError, match="Unknown detection categor"):
        SecurityConfig(enabled_detection_categories={"xss", "not_a_real_category"})


def test_enabled_detection_categories_empty_set_is_valid() -> None:
    config = SecurityConfig(enabled_detection_categories=set())
    assert config.enabled_detection_categories == set()
