from ipaddress import ip_address
from unittest.mock import MagicMock

from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.helpers import (
    _check_ip_blacklist,
    _check_ip_whitelist,
    _get_detection_disabled_reason,
    _get_effective_penetration_setting,
    check_country_access,
    check_route_ip_access,
    check_user_agent_allowed,
    detect_penetration_patterns,
    is_ip_in_blacklist,
    is_ip_in_whitelist,
    is_referrer_domain_allowed,
    validate_auth_header,
)
from guard_core.sync.decorators.base import RouteConfig


def test_is_ip_in_blacklist_exact_match() -> None:
    assert is_ip_in_blacklist("1.2.3.4", ip_address("1.2.3.4"), ["1.2.3.4"]) is True


def test_is_ip_in_blacklist_cidr_match() -> None:
    assert (
        is_ip_in_blacklist("10.0.0.5", ip_address("10.0.0.5"), ["10.0.0.0/8"]) is True
    )


def test_is_ip_in_blacklist_no_match() -> None:
    assert is_ip_in_blacklist("5.5.5.5", ip_address("5.5.5.5"), ["1.2.3.4"]) is False


def test_is_ip_in_whitelist_empty() -> None:
    assert is_ip_in_whitelist("1.2.3.4", ip_address("1.2.3.4"), []) is None


def test_is_ip_in_whitelist_exact_match() -> None:
    assert is_ip_in_whitelist("1.2.3.4", ip_address("1.2.3.4"), ["1.2.3.4"]) is True


def test_is_ip_in_whitelist_cidr_match() -> None:
    assert (
        is_ip_in_whitelist("10.0.0.5", ip_address("10.0.0.5"), ["10.0.0.0/8"]) is True
    )


def test_is_ip_in_whitelist_no_match() -> None:
    assert is_ip_in_whitelist("5.5.5.5", ip_address("5.5.5.5"), ["1.2.3.4"]) is False


def test_check_country_access_no_handler() -> None:
    rc = RouteConfig()
    assert check_country_access("1.2.3.4", rc, None) is None


def test_check_country_access_blocked() -> None:
    rc = RouteConfig()
    rc.blocked_countries = ["CN"]
    geo = MagicMock()
    geo.get_country = MagicMock(return_value="CN")
    assert check_country_access("1.2.3.4", rc, geo) is False


def test_check_country_access_not_blocked() -> None:
    rc = RouteConfig()
    rc.blocked_countries = ["CN"]
    geo = MagicMock()
    geo.get_country = MagicMock(return_value="US")
    assert check_country_access("1.2.3.4", rc, geo) is None


def test_check_country_access_whitelisted() -> None:
    rc = RouteConfig()
    rc.whitelist_countries = ["US"]
    geo = MagicMock()
    geo.get_country = MagicMock(return_value="US")
    assert check_country_access("1.2.3.4", rc, geo) is True


def test_check_country_access_not_whitelisted() -> None:
    rc = RouteConfig()
    rc.whitelist_countries = ["US"]
    geo = MagicMock()
    geo.get_country = MagicMock(return_value="CN")
    assert check_country_access("1.2.3.4", rc, geo) is False


def test_check_country_access_whitelist_no_country() -> None:
    rc = RouteConfig()
    rc.whitelist_countries = ["US"]
    geo = MagicMock()
    geo.get_country = MagicMock(return_value=None)
    assert check_country_access("1.2.3.4", rc, geo) is False


def test_check_country_access_blocked_and_whitelisted() -> None:
    rc = RouteConfig()
    rc.blocked_countries = ["CN"]
    rc.whitelist_countries = ["US"]
    geo = MagicMock()
    geo.get_country = MagicMock(return_value="US")
    assert check_country_access("1.2.3.4", rc, geo) is True


def test_check_ip_blacklist_empty() -> None:
    rc = RouteConfig()
    assert _check_ip_blacklist("1.2.3.4", ip_address("1.2.3.4"), rc) is False


def test_check_ip_blacklist_match() -> None:
    rc = RouteConfig()
    rc.ip_blacklist = ["1.2.3.4"]
    assert _check_ip_blacklist("1.2.3.4", ip_address("1.2.3.4"), rc) is True


def test_check_ip_whitelist_empty() -> None:
    rc = RouteConfig()
    result = _check_ip_whitelist("1.2.3.4", ip_address("1.2.3.4"), rc)
    assert result is None


def test_check_route_ip_access_blacklisted() -> None:
    rc = RouteConfig()
    rc.ip_blacklist = ["1.2.3.4"]
    mw = MagicMock()
    mw.geo_ip_handler = None
    result = check_route_ip_access("1.2.3.4", rc, mw)
    assert result is False


def test_check_route_ip_access_whitelisted() -> None:
    rc = RouteConfig()
    rc.ip_whitelist = ["1.2.3.4"]
    mw = MagicMock()
    mw.geo_ip_handler = None
    result = check_route_ip_access("1.2.3.4", rc, mw)
    assert result is True


def test_check_route_ip_access_invalid_ip() -> None:
    rc = RouteConfig()
    mw = MagicMock()
    result = check_route_ip_access("not_an_ip", rc, mw)
    assert result is False


def test_check_route_ip_access_no_restrictions() -> None:
    rc = RouteConfig()
    mw = MagicMock()
    mw.geo_ip_handler = None
    result = check_route_ip_access("1.2.3.4", rc, mw)
    assert result is None


def test_check_route_ip_access_country() -> None:
    rc = RouteConfig()
    rc.blocked_countries = ["CN"]
    mw = MagicMock()
    mw.geo_ip_handler = MagicMock()
    mw.geo_ip_handler.get_country = MagicMock(return_value="CN")
    result = check_route_ip_access("1.2.3.4", rc, mw)
    assert result is False


def test_check_user_agent_blocked_by_route() -> None:
    rc = RouteConfig()
    rc.blocked_user_agents = ["badbot"]
    config = MagicMock()
    result = check_user_agent_allowed("badbot/1.0", rc, config)
    assert result is False


def test_check_user_agent_allowed_by_route() -> None:
    rc = RouteConfig()
    rc.blocked_user_agents = ["badbot"]
    config = SecurityConfig(enable_redis=False)
    result = check_user_agent_allowed("Mozilla/5.0", rc, config)
    assert result is True


def test_validate_auth_bearer_valid() -> None:
    valid, msg = validate_auth_header("Bearer token123", "bearer")
    assert valid is True
    assert msg == ""


def test_validate_auth_bearer_invalid() -> None:
    valid, msg = validate_auth_header("Basic creds", "bearer")
    assert valid is False
    assert "Bearer" in msg


def test_validate_auth_basic_valid() -> None:
    valid, msg = validate_auth_header("Basic dXNlcjpwYXNz", "basic")
    assert valid is True


def test_validate_auth_basic_invalid() -> None:
    valid, msg = validate_auth_header("Bearer token", "basic")
    assert valid is False
    assert "Basic" in msg


def test_validate_auth_custom_valid() -> None:
    valid, msg = validate_auth_header("CustomScheme value", "custom")
    assert valid is True


def test_validate_auth_custom_empty() -> None:
    valid, msg = validate_auth_header("", "custom")
    assert valid is False
    assert "custom" in msg


def test_referrer_domain_valid() -> None:
    assert (
        is_referrer_domain_allowed("https://example.com/page", ["example.com"]) is True
    )


def test_referrer_domain_subdomain() -> None:
    assert (
        is_referrer_domain_allowed("https://sub.example.com/", ["example.com"]) is True
    )


def test_referrer_domain_invalid() -> None:
    assert is_referrer_domain_allowed("https://evil.com/", ["example.com"]) is False


def test_referrer_domain_bad_url() -> None:
    assert (
        is_referrer_domain_allowed("not a url at all \\x00", ["example.com"]) is False
    )


def test_get_effective_penetration_setting_default() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=True)
    enabled, route_specific = _get_effective_penetration_setting(config, None)
    assert enabled is True
    assert route_specific is None


def test_get_effective_penetration_setting_route_override() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=True)
    rc = RouteConfig()
    rc.enable_suspicious_detection = False
    enabled, route_specific = _get_effective_penetration_setting(config, rc)
    assert enabled is False
    assert route_specific is False


def test_get_detection_disabled_reason_route_override() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=True)
    reason = _get_detection_disabled_reason(config, False)
    assert reason == "disabled_by_decorator"


def test_get_detection_disabled_reason_not_enabled() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=False)
    reason = _get_detection_disabled_reason(config, None)
    assert reason == "not_enabled"


def test_detect_penetration_patterns_enabled() -> None:
    from unittest.mock import patch

    config = SecurityConfig(enable_redis=False, enable_penetration_detection=True)
    from tests.test_sync.conftest import SyncMockGuardRequest

    req = SyncMockGuardRequest(path="/test")
    with patch(
        "guard_core.sync.core.checks.helpers.detect_penetration_attempt",
        return_value=(False, ""),
    ):
        result, info = detect_penetration_patterns(req, None, config, lambda *a: False)
    assert result is False


def test_detect_penetration_patterns_disabled() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=False)
    from tests.test_sync.conftest import SyncMockGuardRequest

    req = SyncMockGuardRequest(path="/test")
    result, info = detect_penetration_patterns(req, None, config, lambda *a: False)
    assert result is False
    assert info == "not_enabled"


def test_detect_penetration_patterns_bypassed() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=True)
    from tests.test_sync.conftest import SyncMockGuardRequest

    req = SyncMockGuardRequest(path="/test")
    result, info = detect_penetration_patterns(req, None, config, lambda *a: True)
    assert result is False
