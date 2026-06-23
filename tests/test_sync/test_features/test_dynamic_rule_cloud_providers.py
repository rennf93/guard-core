import logging

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager


@pytest.fixture
def manager() -> DynamicRuleManager:
    config = SecurityConfig(enable_redis=False)
    return DynamicRuleManager(config)


def test_apply_cloud_provider_rules_filters_invalid_providers(
    manager: DynamicRuleManager, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING)
    manager._apply_cloud_provider_rules({"AWS", "Bogus", "GCP"})
    assert manager.config.block_cloud_providers == {"AWS", "GCP"}
    assert "ignored unknown cloud providers" in caplog.text
    assert "Bogus" in caplog.text


def test_apply_cloud_provider_rules_all_valid(
    manager: DynamicRuleManager,
) -> None:
    manager._apply_cloud_provider_rules({"AWS", "GCP", "Azure"})
    assert manager.config.block_cloud_providers == {"AWS", "GCP", "Azure"}


def test_apply_cloud_provider_rules_empty_set(
    manager: DynamicRuleManager,
) -> None:
    manager._apply_cloud_provider_rules(set())
    assert manager.config.block_cloud_providers == set()


def test_apply_cloud_provider_rules_all_invalid(
    manager: DynamicRuleManager, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING)
    manager._apply_cloud_provider_rules({"Bogus1", "Bogus2"})
    assert manager.config.block_cloud_providers == set()
    assert "ignored unknown cloud providers" in caplog.text
