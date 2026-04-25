import re
from unittest.mock import MagicMock, Mock, patch

from guard_core.models import SecurityConfig
from guard_core.sync.core.events.middleware_events import SecurityEventBus
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager
from guard_core.sync.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager


def test_send_rule_received_event_no_agent() -> None:
    from datetime import datetime, timezone

    config = SecurityConfig()
    config.enable_dynamic_rules = False
    manager = DynamicRuleManager(config)
    manager.agent_handler = None

    from guard_core.models import DynamicRules

    rules = DynamicRules(
        rule_id="test", version=1, timestamp=datetime.now(timezone.utc)
    )

    manager._send_rule_received_event(rules)

    assert True


def test_get_redis_request_count_no_redis_handler() -> None:
    config = SecurityConfig()
    config.enable_redis = False
    manager = RateLimitManager(config)
    manager.redis_handler = None

    result = manager._get_redis_request_count(
        client_ip="127.0.0.1", current_time=1000.0, window_start=900.0
    )

    assert result is None


def test_get_validated_cors_config_no_cors_config() -> None:
    manager = SecurityHeadersManager()
    manager.cors_config = None

    allow_methods, allow_headers = manager._get_validated_cors_config()

    assert allow_methods == ["GET", "POST"]
    assert allow_headers == ["*"]


def test_remove_default_pattern_not_found() -> None:
    handler = SusPatternsManager()

    original_patterns = handler.patterns.copy()
    original_compiled = handler.compiled_patterns.copy()

    try:
        result = handler._remove_default_pattern("nonexistent_pattern_xyz")

        assert result is False
    finally:
        handler.patterns = original_patterns
        handler.compiled_patterns = original_compiled


def test_remove_default_pattern_invalid_index() -> None:
    handler = SusPatternsManager()

    original_patterns = handler.patterns.copy()
    original_compiled = handler.compiled_patterns.copy()

    try:
        test_pattern = "test_pattern_xyz_123_unique_edge"
        handler.patterns.append(test_pattern)
        compiled = re.compile(test_pattern)
        handler.compiled_patterns.append(compiled)

        handler.compiled_patterns = []

        result = handler._remove_default_pattern(test_pattern)

        assert result is False
    finally:
        handler.patterns = original_patterns
        handler.compiled_patterns = original_compiled


def test_fallback_pattern_check_with_exception() -> None:
    from guard_core.sync.utils import _fallback_pattern_check

    with patch(
        "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_handler:
        mock_pattern = Mock()
        mock_pattern.search = Mock(side_effect=Exception("Pattern error"))
        mock_handler.get_all_compiled_patterns = MagicMock(
            return_value=[(mock_pattern, frozenset({"unknown"}), "custom")]
        )

        result = _fallback_pattern_check("test_value")

        assert result == (False, "")


def test_check_value_enhanced_empty_threats_list() -> None:
    from guard_core.sync.utils import _check_value_enhanced

    with patch(
        "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_handler:
        mock_handler.detect = MagicMock(return_value={"is_threat": True, "threats": []})

        result = _check_value_enhanced(
            value="test_value",
            context="test_context",
            client_ip="127.0.0.1",
            correlation_id="test-123",
        )

        assert result == (True, "Threat detected", [])


def test_detect_penetration_attempt_real_path() -> None:
    from guard_core.sync.detection_result import DetectionResult
    from guard_core.sync.utils import detect_penetration_attempt

    mock_request = Mock()
    mock_request.client_host = "127.0.0.1"
    mock_request.query_params = {}
    mock_request.url_path = "/test"
    mock_request.headers = {}
    mock_request.body = MagicMock(return_value=b"")

    result = detect_penetration_attempt(mock_request)

    assert isinstance(result, DetectionResult)
    assert isinstance(result.is_threat, bool)
    assert isinstance(result.trigger_info, str)


def test_send_middleware_event_with_geo_ip_exception() -> None:
    config = SecurityConfig()
    config.agent_enable_events = True

    mock_agent = Mock()
    mock_agent.send_event = MagicMock()

    mock_geo_ip = Mock()
    geo_exception = Exception("GeoIP failure")
    mock_geo_ip.get_country = Mock(side_effect=geo_exception)

    event_bus = SecurityEventBus(mock_agent, config, mock_geo_ip)

    mock_request = Mock()
    mock_request.client_host = "192.168.1.1"
    mock_request.state.client_ip = None
    mock_request.url_path = "/test"
    mock_request.method = "GET"
    mock_request.headers = {"User-Agent": "TestAgent"}

    event_bus.send_middleware_event(
        event_type="suspicious_request",
        request=mock_request,
        action_taken="logged",
        reason="test reason",
    )

    assert mock_agent.send_event.call_count == 1


def test_integration_all_edge_cases() -> None:
    from datetime import datetime, timezone

    config = SecurityConfig()
    config.enable_redis = False
    config.enable_agent = False
    config.enable_dynamic_rules = False

    drm = DynamicRuleManager(config)
    from guard_core.models import DynamicRules

    rules = DynamicRules(
        rule_id="test", version=1, timestamp=datetime.now(timezone.utc)
    )
    drm._send_rule_received_event(rules)

    rlm = RateLimitManager(config)
    result = rlm._get_redis_request_count("127.0.0.1", 1000.0, 900.0)
    assert result is None

    shm = SecurityHeadersManager()
    shm.cors_config = None
    methods, headers = shm._get_validated_cors_config()
    assert methods == ["GET", "POST"]
    assert headers == ["*"]

    spm = SusPatternsManager()
    result = spm._remove_default_pattern("nonexistent")
    assert result is False
