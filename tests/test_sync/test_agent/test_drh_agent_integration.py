import logging
import threading
import time
from collections.abc import Generator
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import DynamicRules, SecurityConfig
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager


@pytest.fixture
def sample_rules() -> DynamicRules:
    return DynamicRules(
        rule_id="test-rule-123",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=["172.16.0.100", "10.0.0.50"],
        ip_whitelist=["192.168.1.200"],
        blocked_countries=["XX", "YY"],
        whitelist_countries=["US", "CA"],
        global_rate_limit=50,
        global_rate_window=30,
        endpoint_rate_limits={"/api/endpoint": (10, 60)},
        blocked_cloud_providers={"aws", "azure"},
        blocked_user_agents=["badbot", "scanner"],
        suspicious_patterns=["../", "SELECT * FROM"],
        enable_penetration_detection=True,
        enable_ip_banning=True,
        enable_rate_limiting=True,
        emergency_mode=False,
        emergency_whitelist=[],
        ip_ban_duration=3600,
    )


@pytest.fixture
def cleanup_singleton() -> Generator[Any, Any, Any]:
    DynamicRuleManager._instance = None
    yield
    DynamicRuleManager._instance = None


def test_singleton_pattern(
    config: SecurityConfig, cleanup_singleton: Generator[Any, Any, Any]
) -> None:
    DynamicRuleManager._instance = None

    instance1 = DynamicRuleManager(config)
    instance2 = DynamicRuleManager(config)

    assert instance1 is instance2
    assert DynamicRuleManager._instance is instance1


def test_singleton_preserves_state(config: SecurityConfig) -> None:
    DynamicRuleManager._instance = None

    instance1 = DynamicRuleManager(config)
    instance1.last_update = 12345.67
    test_rules = MagicMock()
    instance1.current_rules = test_rules

    instance2 = DynamicRuleManager(config)

    assert instance2.last_update == 12345.67
    assert instance2.current_rules is test_rules


def test_initialize_agent_with_dynamic_rules_enabled(
    config: SecurityConfig, mock_agent_handler: MagicMock
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    manager.initialize_agent(mock_agent_handler)

    assert manager.agent_handler is mock_agent_handler

    assert manager.update_task is not None
    assert isinstance(manager.update_task, threading.Thread)

    manager.update_task.join(timeout=1)


def test_initialize_agent_with_dynamic_rules_disabled(
    config: SecurityConfig, mock_agent_handler: MagicMock
) -> None:
    DynamicRuleManager._instance = None

    config.enable_dynamic_rules = False

    manager = DynamicRuleManager(config)

    manager.initialize_agent(mock_agent_handler)

    assert manager.agent_handler is mock_agent_handler

    assert manager.update_task is None


def test_initialize_agent_prevents_duplicate_tasks(
    config: SecurityConfig, mock_agent_handler: MagicMock
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    manager.initialize_agent(mock_agent_handler)
    first_task = manager.update_task

    manager.initialize_agent(mock_agent_handler)
    second_task = manager.update_task

    assert first_task is second_task

    if manager.update_task:
        manager.update_task.join(timeout=1)


def test_initialize_redis(
    config: SecurityConfig, mock_redis_handler: MagicMock
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    manager.initialize_redis(mock_redis_handler)

    assert manager.redis_handler is mock_redis_handler


def test_rule_update_loop_normal_operation(
    config: SecurityConfig,
) -> None:
    DynamicRuleManager._instance = None

    config.dynamic_rule_interval = 1
    manager = DynamicRuleManager(config)

    update_count = 0

    def mock_update_rules() -> None:
        nonlocal update_count
        update_count += 1
        if update_count >= 2:
            return

    with patch.object(manager, "update_rules", mock_update_rules):
        loop_task = threading.Thread(target=manager._rule_update_loop, daemon=True)

        loop_task.start()

        time.sleep(2.5)

        loop_task.join(timeout=1)

    assert update_count >= 2


def test_rule_update_loop_handles_exceptions(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    config.dynamic_rule_interval = 1

    manager = DynamicRuleManager(config)

    call_count = 0

    def mock_update_rules() -> None:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise Exception("Test exception")

    with patch.object(manager, "update_rules", mock_update_rules):
        with caplog.at_level(logging.ERROR):
            loop_task = threading.Thread(target=manager._rule_update_loop, daemon=True)

            loop_task.start()

            time.sleep(2.5)

            loop_task.join(timeout=1)

    assert "Error in dynamic rule update loop: Test exception" in caplog.text
    assert call_count >= 1


def test_update_rules_disabled(
    config: SecurityConfig, mock_agent_handler: MagicMock
) -> None:
    DynamicRuleManager._instance = None

    config.enable_dynamic_rules = False
    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    manager.update_rules()

    mock_agent_handler.get_dynamic_rules.assert_not_called()


def test_update_rules_no_agent(config: SecurityConfig) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = None

    manager.update_rules()

    assert manager.current_rules is None


def test_update_rules_no_rules_returned(
    config: SecurityConfig, mock_agent_handler: MagicMock
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    mock_agent_handler.get_dynamic_rules.return_value = None

    manager.update_rules()

    assert manager.current_rules is None
    assert manager.last_update == 0


def test_update_rules_same_version(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler
    manager.current_rules = sample_rules

    mock_agent_handler.get_dynamic_rules.return_value = sample_rules

    manager.update_rules()

    assert manager.current_rules is sample_rules
    assert manager.last_update == 0


def test_update_rules_older_version(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    current_rules = sample_rules.model_copy()
    current_rules.version = 2
    manager.current_rules = current_rules

    mock_agent_handler.get_dynamic_rules.return_value = sample_rules

    manager.update_rules()

    assert manager.current_rules is not None
    assert manager.current_rules.version == 2
    assert manager.last_update == 0


def test_update_rules_success(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
    caplog: pytest.LogCaptureFixture,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    with (
        patch.object(manager, "_apply_rules", MagicMock()) as mock_apply_rules,
        patch.object(
            manager, "_send_rule_applied_event", MagicMock()
        ) as mock_send_event,
    ):
        mock_agent_handler.get_dynamic_rules.return_value = sample_rules

        with caplog.at_level(logging.INFO):
            manager.update_rules()

        mock_apply_rules.assert_called_once_with(sample_rules)

        assert manager.current_rules == sample_rules
        assert manager.last_update > 0

        mock_send_event.assert_called_once_with(sample_rules)

    assert (
        f"Applying dynamic rules: {sample_rules.rule_id} v{sample_rules.version}"
        in caplog.text
    )


def test_update_rules_dynamic_rule_updated_event_failure(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
    caplog: pytest.LogCaptureFixture,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    current_rules = sample_rules.model_copy()
    current_rules.version = 1
    manager.current_rules = current_rules

    sample_rules.version = 2

    mock_agent_handler.get_dynamic_rules.return_value = sample_rules

    mock_agent_handler.send_event.side_effect = Exception("Network error")

    with (
        patch.object(manager, "_apply_rules", MagicMock()) as mock_apply_rules,
        patch.object(
            manager, "_send_rule_applied_event", MagicMock()
        ) as mock_send_event,
    ):
        with caplog.at_level(logging.ERROR):
            manager.update_rules()

        mock_agent_handler.send_event.assert_called_once()
        sent_event = mock_agent_handler.send_event.call_args[0][0]
        assert sent_event.event_type == "dynamic_rule_updated"
        assert sent_event.action_taken == "rules_received"
        assert "Received updated rules" in sent_event.reason

        assert "Failed to send rule updated event: Network error" in caplog.text

        mock_apply_rules.assert_called_once_with(sample_rules)

        assert manager.current_rules == sample_rules
        assert manager.last_update > 0

        mock_send_event.assert_called_once_with(sample_rules)


def test_update_rules_apply_failure(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
    caplog: pytest.LogCaptureFixture,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    with (
        patch.object(
            manager,
            "_apply_rules",
            MagicMock(side_effect=Exception("Apply failed")),
        ),
        patch.object(
            manager, "_send_rule_applied_event", MagicMock()
        ) as mock_send_event,
    ):
        mock_agent_handler.get_dynamic_rules.return_value = sample_rules

        with caplog.at_level(logging.ERROR):
            manager.update_rules()

        assert "Failed to update dynamic rules: Apply failed" in caplog.text

        assert manager.current_rules is None
        assert manager.last_update == 0

        mock_send_event.assert_not_called()


def test_update_rules_different_rule_id(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    current_rules = sample_rules.model_copy()
    current_rules.rule_id = "different-rule-456"
    manager.current_rules = current_rules

    with (
        patch.object(manager, "_apply_rules", MagicMock()) as mock_apply_rules,
        patch.object(manager, "_send_rule_applied_event", MagicMock()),
    ):
        mock_agent_handler.get_dynamic_rules.return_value = sample_rules

        manager.update_rules()

        mock_apply_rules.assert_called_once_with(sample_rules)
        assert manager.current_rules == sample_rules


def test_apply_rules_all_types(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    with (
        patch.object(manager, "_apply_ip_bans", MagicMock()) as mock_ip_bans,
        patch.object(manager, "_apply_ip_whitelist", MagicMock()) as mock_ip_whitelist,
        patch.object(
            manager, "_apply_country_rules", MagicMock()
        ) as mock_country_rules,
        patch.object(
            manager, "_apply_rate_limit_rules", MagicMock()
        ) as mock_rate_limit_rules,
        patch.object(
            manager, "_apply_cloud_provider_rules", MagicMock()
        ) as mock_cloud_provider_rules,
        patch.object(
            manager, "_apply_user_agent_rules", MagicMock()
        ) as mock_user_agent_rules,
        patch.object(
            manager, "_apply_pattern_rules", MagicMock()
        ) as mock_pattern_rules,
        patch.object(
            manager, "_apply_feature_toggles", MagicMock()
        ) as mock_feature_toggles,
        patch.object(
            manager, "_activate_emergency_mode", MagicMock()
        ) as mock_emergency_mode,
    ):
        manager._apply_rules(sample_rules)

        mock_ip_bans.assert_called_once_with(
            sample_rules.ip_blacklist, sample_rules.ip_ban_duration
        )
        mock_ip_whitelist.assert_called_once_with(sample_rules.ip_whitelist)
        mock_country_rules.assert_called_once_with(
            sample_rules.blocked_countries, sample_rules.whitelist_countries
        )
        mock_rate_limit_rules.assert_called_once_with(sample_rules)
        mock_cloud_provider_rules.assert_called_once_with(
            sample_rules.blocked_cloud_providers
        )
        mock_user_agent_rules.assert_called_once_with(sample_rules.blocked_user_agents)
        mock_pattern_rules.assert_called_once_with(sample_rules.suspicious_patterns)
        mock_feature_toggles.assert_called_once_with(sample_rules)
        mock_emergency_mode.assert_not_called()


def test_apply_rules_emergency_mode(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    sample_rules.emergency_mode = True
    sample_rules.emergency_whitelist = ["192.168.1.1", "10.0.0.1"]

    with patch.object(
        manager, "_activate_emergency_mode", MagicMock()
    ) as mock_emergency_mode:
        manager._apply_rules(sample_rules)

        mock_emergency_mode.assert_called_once_with(sample_rules.emergency_whitelist)


def test_apply_rules_partial(
    config: SecurityConfig, mock_agent_handler: MagicMock
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    partial_rules = DynamicRules(
        rule_id="partial-123",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=["172.16.0.100"],
        ip_whitelist=[],
        blocked_countries=[],
        whitelist_countries=[],
        global_rate_limit=None,
        global_rate_window=None,
        endpoint_rate_limits={},
        blocked_cloud_providers=set(),
        blocked_user_agents=[],
        suspicious_patterns=[],
        enable_penetration_detection=None,
        enable_ip_banning=None,
        enable_rate_limiting=None,
        emergency_mode=False,
        emergency_whitelist=[],
        ip_ban_duration=3600,
    )

    with (
        patch.object(manager, "_apply_ip_bans", MagicMock()) as mock_ip_bans,
        patch.object(manager, "_apply_ip_whitelist", MagicMock()) as mock_ip_whitelist,
        patch.object(
            manager, "_apply_country_rules", MagicMock()
        ) as mock_country_rules,
        patch.object(
            manager, "_apply_rate_limit_rules", MagicMock()
        ) as mock_rate_limit_rules,
        patch.object(
            manager, "_apply_cloud_provider_rules", MagicMock()
        ) as mock_cloud_provider_rules,
        patch.object(
            manager, "_apply_user_agent_rules", MagicMock()
        ) as mock_user_agent_rules,
        patch.object(
            manager, "_apply_pattern_rules", MagicMock()
        ) as mock_pattern_rules,
        patch.object(
            manager, "_apply_feature_toggles", MagicMock()
        ) as mock_feature_toggles,
    ):
        manager._apply_rules(partial_rules)

        mock_ip_bans.assert_called_once()
        mock_ip_whitelist.assert_not_called()
        mock_country_rules.assert_not_called()
        mock_rate_limit_rules.assert_not_called()
        mock_cloud_provider_rules.assert_not_called()
        mock_user_agent_rules.assert_not_called()
        mock_pattern_rules.assert_not_called()
        mock_feature_toggles.assert_called_once()


def test_apply_rules_exception_handling(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
    caplog: pytest.LogCaptureFixture,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    with patch.object(
        manager, "_apply_ip_bans", MagicMock(side_effect=Exception("IP ban failed"))
    ):
        with caplog.at_level(logging.ERROR):
            with pytest.raises(Exception, match="IP ban failed"):
                manager._apply_rules(sample_rules)

    assert "Failed to apply dynamic rules: IP ban failed" in caplog.text


def test_apply_ip_bans_success(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    with patch(
        "guard_core.sync.handlers.ipban_handler.ip_ban_manager"
    ) as mock_ban_manager:
        mock_ban_manager.ban_ip = MagicMock()

        ip_list = ["172.16.0.100", "10.0.0.50"]
        duration = 3600

        with caplog.at_level(logging.INFO):
            manager._apply_ip_bans(ip_list, duration)

        assert mock_ban_manager.ban_ip.call_count == 2
        mock_ban_manager.ban_ip.assert_any_call("172.16.0.100", 3600, "dynamic_rule")
        mock_ban_manager.ban_ip.assert_any_call("10.0.0.50", 3600, "dynamic_rule")

        assert "Dynamic rule: Banned IP 172.16.0.100 for 3600s" in caplog.text
        assert "Dynamic rule: Banned IP 10.0.0.50 for 3600s" in caplog.text


def test_apply_ip_bans_with_failures(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    with patch(
        "guard_core.sync.handlers.ipban_handler.ip_ban_manager"
    ) as mock_ban_manager:
        mock_ban_manager.ban_ip = MagicMock(side_effect=[None, Exception("Ban failed")])

        ip_list = ["172.16.0.100", "10.0.0.50"]
        duration = 3600

        with caplog.at_level(logging.ERROR):
            manager._apply_ip_bans(ip_list, duration)

        assert mock_ban_manager.ban_ip.call_count == 2

        assert "Failed to ban IP 10.0.0.50: Ban failed" in caplog.text


def test_apply_ip_whitelist_success(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    with patch(
        "guard_core.sync.handlers.ipban_handler.ip_ban_manager"
    ) as mock_ban_manager:
        mock_ban_manager.unban_ip = MagicMock()

        ip_list = ["192.168.1.200", "10.0.0.100"]

        with caplog.at_level(logging.INFO):
            manager._apply_ip_whitelist(ip_list)

        assert mock_ban_manager.unban_ip.call_count == 2
        mock_ban_manager.unban_ip.assert_any_call("192.168.1.200")
        mock_ban_manager.unban_ip.assert_any_call("10.0.0.100")

        assert "Dynamic rule: Whitelisted IP 192.168.1.200" in caplog.text
        assert "Dynamic rule: Whitelisted IP 10.0.0.100" in caplog.text


def test_apply_ip_whitelist_with_failures(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    with patch(
        "guard_core.sync.handlers.ipban_handler.ip_ban_manager"
    ) as mock_ban_manager:
        mock_ban_manager.unban_ip = MagicMock(side_effect=Exception("Unban failed"))

        ip_list = ["192.168.1.200"]

        with caplog.at_level(logging.ERROR):
            manager._apply_ip_whitelist(ip_list)

        assert "Failed to whitelist IP 192.168.1.200: Unban failed" in caplog.text


def test_apply_country_rules_blocked_only(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    blocked = ["XX", "YY"]
    allowed: list[str] = []

    with caplog.at_level(logging.INFO):
        manager._apply_country_rules(blocked, allowed)

    assert manager.config.blocked_countries == blocked

    assert "Dynamic rule: Blocked countries ['XX', 'YY']" in caplog.text


def test_apply_country_rules_allowed_only(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    blocked: list[str] = []
    allowed = ["US", "CA"]

    with caplog.at_level(logging.INFO):
        manager._apply_country_rules(blocked, allowed)

    assert manager.config.whitelist_countries == allowed

    assert "Dynamic rule: Whitelisted countries ['US', 'CA']" in caplog.text


def test_apply_country_rules_both(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    blocked = ["XX", "YY"]
    allowed = ["US", "CA"]

    with caplog.at_level(logging.INFO):
        manager._apply_country_rules(blocked, allowed)

    assert manager.config.blocked_countries == blocked
    assert manager.config.whitelist_countries == allowed

    assert "Dynamic rule: Blocked countries ['XX', 'YY']" in caplog.text
    assert "Dynamic rule: Whitelisted countries ['US', 'CA']" in caplog.text


def test_apply_rate_limit_global_only(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    rules = DynamicRules(
        rule_id="rate-123",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=[],
        ip_whitelist=[],
        blocked_countries=[],
        whitelist_countries=[],
        global_rate_limit=50,
        global_rate_window=30,
        endpoint_rate_limits={},
        blocked_cloud_providers=set(),
        blocked_user_agents=[],
        suspicious_patterns=[],
        enable_penetration_detection=None,
        enable_ip_banning=None,
        enable_rate_limiting=None,
        emergency_mode=False,
        emergency_whitelist=[],
        ip_ban_duration=3600,
    )

    with caplog.at_level(logging.INFO):
        manager._apply_rate_limit_rules(rules)

    assert manager.config.rate_limit == 50
    assert manager.config.rate_limit_window == 30

    assert "Dynamic rule: Global rate limit 50 per 30s" in caplog.text


def test_apply_rate_limit_endpoint_only(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    rules = DynamicRules(
        rule_id="rate-123",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=[],
        ip_whitelist=[],
        blocked_countries=[],
        whitelist_countries=[],
        global_rate_limit=None,
        global_rate_window=None,
        endpoint_rate_limits={"/api/v1": (10, 60), "/api/v2": (20, 60)},
        blocked_cloud_providers=set(),
        blocked_user_agents=[],
        suspicious_patterns=[],
        enable_penetration_detection=None,
        enable_ip_banning=None,
        enable_rate_limiting=None,
        emergency_mode=False,
        emergency_whitelist=[],
        ip_ban_duration=3600,
    )

    with caplog.at_level(logging.INFO):
        manager._apply_rate_limit_rules(rules)

    assert manager.config.endpoint_rate_limits == rules.endpoint_rate_limits

    assert (
        "Dynamic rule: Applied endpoint-specific rate limits for 2 endpoints"
        in caplog.text
    )
    assert "['/api/v1', '/api/v2']" in caplog.text


def test_apply_rate_limit_both(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    rules = DynamicRules(
        rule_id="rate-123",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=[],
        ip_whitelist=[],
        blocked_countries=[],
        whitelist_countries=[],
        global_rate_limit=100,
        global_rate_window=60,
        endpoint_rate_limits={"/api/endpoint": (10, 30)},
        blocked_cloud_providers=set(),
        blocked_user_agents=[],
        suspicious_patterns=[],
        enable_penetration_detection=None,
        enable_ip_banning=None,
        enable_rate_limiting=None,
        emergency_mode=False,
        emergency_whitelist=[],
        ip_ban_duration=3600,
    )

    with caplog.at_level(logging.INFO):
        manager._apply_rate_limit_rules(rules)

    assert manager.config.rate_limit == 100
    assert manager.config.rate_limit_window == 60
    assert manager.config.endpoint_rate_limits == rules.endpoint_rate_limits


def test_apply_cloud_provider_rules(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    providers = {"aws", "azure", "gcp"}

    with caplog.at_level(logging.INFO):
        manager._apply_cloud_provider_rules(providers)

    assert manager.config.block_cloud_providers == providers


def test_apply_user_agent_rules(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    user_agents = ["badbot", "scanner", "scraper"]

    with caplog.at_level(logging.INFO):
        manager._apply_user_agent_rules(user_agents)

    assert manager.config.blocked_user_agents == user_agents

    assert (
        "Dynamic rule: Blocked user agents ['badbot', 'scanner', 'scraper']"
        in caplog.text
    )


def test_apply_pattern_rules(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    patterns = ["../", "SELECT * FROM", "<script>"]

    with patch(
        "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_patterns:
        mock_patterns.add_pattern = MagicMock()

        with caplog.at_level(logging.INFO):
            manager._apply_pattern_rules(patterns)

        assert mock_patterns.add_pattern.call_count == 3
        mock_patterns.add_pattern.assert_any_call("../")
        mock_patterns.add_pattern.assert_any_call("SELECT * FROM")
        mock_patterns.add_pattern.assert_any_call("<script>")

        assert (
            "Dynamic rule: Added suspicious patterns "
            "['../', 'SELECT * FROM', '<script>']" in caplog.text
        )


def test_apply_feature_toggles_all_enabled(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    rules = DynamicRules(
        rule_id="toggle-123",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=[],
        ip_whitelist=[],
        blocked_countries=[],
        whitelist_countries=[],
        global_rate_limit=None,
        global_rate_window=None,
        endpoint_rate_limits={},
        blocked_cloud_providers=set(),
        blocked_user_agents=[],
        suspicious_patterns=[],
        enable_penetration_detection=True,
        enable_ip_banning=True,
        enable_rate_limiting=True,
        emergency_mode=False,
        emergency_whitelist=[],
        ip_ban_duration=3600,
    )

    with caplog.at_level(logging.INFO):
        manager._apply_feature_toggles(rules)

    assert manager.config.enable_penetration_detection is True
    assert manager.config.enable_ip_banning is True
    assert manager.config.enable_rate_limiting is True

    assert "Dynamic rule: Penetration detection True" in caplog.text
    assert "Dynamic rule: IP banning True" in caplog.text
    assert "Dynamic rule: Rate limiting True" in caplog.text


def test_apply_feature_toggles_all_disabled(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    rules = DynamicRules(
        rule_id="toggle-123",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=[],
        ip_whitelist=[],
        blocked_countries=[],
        whitelist_countries=[],
        global_rate_limit=None,
        global_rate_window=None,
        endpoint_rate_limits={},
        blocked_cloud_providers=set(),
        blocked_user_agents=[],
        suspicious_patterns=[],
        enable_penetration_detection=False,
        enable_ip_banning=False,
        enable_rate_limiting=False,
        emergency_mode=False,
        emergency_whitelist=[],
        ip_ban_duration=3600,
    )

    with caplog.at_level(logging.INFO):
        manager._apply_feature_toggles(rules)

    assert manager.config.enable_penetration_detection is False
    assert manager.config.enable_ip_banning is False
    assert manager.config.enable_rate_limiting is False

    assert "Dynamic rule: Penetration detection False" in caplog.text
    assert "Dynamic rule: IP banning False" in caplog.text
    assert "Dynamic rule: Rate limiting False" in caplog.text


def test_apply_feature_toggles_none_values(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    orig_pen = config.enable_penetration_detection
    orig_ban = config.enable_ip_banning
    orig_rate = config.enable_rate_limiting

    rules = DynamicRules(
        rule_id="toggle-123",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=[],
        ip_whitelist=[],
        blocked_countries=[],
        whitelist_countries=[],
        global_rate_limit=None,
        global_rate_window=None,
        endpoint_rate_limits={},
        blocked_cloud_providers=set(),
        blocked_user_agents=[],
        suspicious_patterns=[],
        enable_penetration_detection=None,
        enable_ip_banning=None,
        enable_rate_limiting=None,
        emergency_mode=False,
        emergency_whitelist=[],
        ip_ban_duration=3600,
    )

    with caplog.at_level(logging.INFO):
        manager._apply_feature_toggles(rules)

    assert manager.config.enable_penetration_detection == orig_pen
    assert manager.config.enable_ip_banning == orig_ban
    assert manager.config.enable_rate_limiting == orig_rate

    assert "Dynamic rule: Penetration detection" not in caplog.text
    assert "Dynamic rule: IP banning" not in caplog.text
    assert "Dynamic rule: Rate limiting" not in caplog.text


def test_activate_emergency_mode_with_agent(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    with patch.object(manager, "_send_emergency_event", MagicMock()) as mock_send_event:
        config.auto_ban_threshold = 10

        whitelist = ["192.168.1.1", "10.0.0.1"]

        with caplog.at_level(logging.WARNING):
            manager._activate_emergency_mode(whitelist)

        assert manager.config.emergency_mode is True
        assert manager.config.emergency_whitelist == whitelist
        assert manager.config.auto_ban_threshold == 5

        assert (
            "[EMERGENCY MODE] ACTIVATED - Enhanced security posture enabled"
            in caplog.text
        )
        assert "[EMERGENCY MODE] Reduced auto-ban threshold from 10 to 5" in caplog.text

        mock_send_event.assert_called_once_with(whitelist)


def test_activate_emergency_mode_without_agent(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = None

    config.auto_ban_threshold = 3

    whitelist = ["192.168.1.1"]

    with caplog.at_level(logging.CRITICAL):
        manager._activate_emergency_mode(whitelist)

    assert manager.config.emergency_mode is True
    assert manager.config.emergency_whitelist == whitelist
    assert manager.config.auto_ban_threshold == 1


def test_activate_emergency_mode_minimum_threshold(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    config.auto_ban_threshold = 1

    whitelist: list[str] = []

    with caplog.at_level(logging.WARNING):
        manager._activate_emergency_mode(whitelist)

    assert manager.config.auto_ban_threshold == 1

    assert "[EMERGENCY MODE] Reduced auto-ban threshold from 1 to 1" in caplog.text


def test_send_rule_applied_event_success(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    manager._send_rule_applied_event(sample_rules)

    mock_agent_handler.send_event.assert_called_once()

    sent_event = mock_agent_handler.send_event.call_args[0][0]
    assert sent_event.event_type == "dynamic_rule_applied"
    assert sent_event.ip_address == "system"
    assert sent_event.action_taken == "rules_updated"
    assert "Applied dynamic rules" in sent_event.reason
    assert sent_event.metadata["rule_id"] == sample_rules.rule_id
    assert sent_event.metadata["version"] == sample_rules.version
    assert sent_event.metadata["ip_bans"] == len(sample_rules.ip_blacklist)
    assert sent_event.metadata["country_blocks"] == len(sample_rules.blocked_countries)
    assert sent_event.metadata["emergency_mode"] == sample_rules.emergency_mode


def test_send_rule_applied_event_no_agent(
    config: SecurityConfig, sample_rules: DynamicRules
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = None

    manager._send_rule_applied_event(sample_rules)


def test_send_rule_applied_event_failure(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
    caplog: pytest.LogCaptureFixture,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    mock_agent_handler.send_event.side_effect = Exception("Send failed")

    with caplog.at_level(logging.ERROR):
        manager._send_rule_applied_event(sample_rules)

    assert "Failed to send rule applied event: Send failed" in caplog.text


def test_send_emergency_event_success(
    config: SecurityConfig, mock_agent_handler: MagicMock
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    whitelist = ["192.168.1.1", "10.0.0.1"]

    manager._send_emergency_event(whitelist)

    mock_agent_handler.send_event.assert_called_once()

    sent_event = mock_agent_handler.send_event.call_args[0][0]
    assert sent_event.event_type == "emergency_mode_activated"
    assert sent_event.ip_address == "system"
    assert sent_event.action_taken == "emergency_lockdown"
    assert "[EMERGENCY MODE] activated" in sent_event.reason
    assert sent_event.metadata["whitelist_count"] == 2
    assert sent_event.metadata["whitelist"] == whitelist


def test_send_emergency_event_large_whitelist(
    config: SecurityConfig, mock_agent_handler: MagicMock
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    whitelist = [f"192.168.1.{i}" for i in range(20)]

    manager._send_emergency_event(whitelist)

    sent_event = mock_agent_handler.send_event.call_args[0][0]
    assert sent_event.metadata["whitelist_count"] == 20
    assert len(sent_event.metadata["whitelist"]) == 10


def test_send_emergency_event_no_agent(config: SecurityConfig) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = None

    manager._send_emergency_event(["192.168.1.1"])


def test_send_emergency_event_failure(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    mock_agent_handler.send_event.side_effect = Exception("Send failed")

    with caplog.at_level(logging.ERROR):
        manager._send_emergency_event(["192.168.1.1"])

    assert "Failed to send emergency event: Send failed" in caplog.text


def test_get_current_rules(config: SecurityConfig, sample_rules: DynamicRules) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    assert manager.get_current_rules() is None

    manager.current_rules = sample_rules

    assert manager.get_current_rules() == sample_rules


def test_force_update(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    with patch.object(manager, "update_rules", MagicMock()) as mock_update_rules:
        manager.force_update()

        mock_update_rules.assert_called_once()


def test_stop_without_task(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.update_task = None

    with caplog.at_level(logging.INFO):
        manager.stop()

    assert manager.update_task is None
    assert "Stopped dynamic rule update loop" not in caplog.text


def test_apply_ip_rules_whitelist_only() -> None:
    from datetime import datetime, timezone
    from unittest.mock import MagicMock, patch

    from guard_core.models import DynamicRules, SecurityConfig
    from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager

    DynamicRuleManager._instance = None
    mgr = DynamicRuleManager(SecurityConfig())
    rules = DynamicRules(
        rule_id="r1",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=[],
        ip_whitelist=["10.0.0.1"],
    )
    with patch(
        "guard_core.sync.handlers.ipban_handler.ip_ban_manager.unban_ip",
        new=MagicMock(),
    ):
        mgr._apply_ip_rules(rules)
    DynamicRuleManager._instance = None


def test_apply_rate_limit_rules_global_without_window() -> None:
    from datetime import datetime, timezone

    from guard_core.models import DynamicRules, SecurityConfig
    from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager

    DynamicRuleManager._instance = None
    mgr = DynamicRuleManager(SecurityConfig())
    rules = DynamicRules(
        rule_id="r1",
        version=1,
        timestamp=datetime.now(timezone.utc),
        global_rate_limit=100,
        global_rate_window=None,
    )
    mgr._apply_rate_limit_rules(rules)
    assert mgr.config.rate_limit == 100
    DynamicRuleManager._instance = None
