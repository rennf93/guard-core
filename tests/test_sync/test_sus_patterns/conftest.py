import os
from collections.abc import Generator

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.ipinfo_handler import IPInfoManager
from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager

IPINFO_TOKEN = str(os.getenv("IPINFO_TOKEN", "test_token"))


@pytest.fixture
def security_config_with_detection() -> SecurityConfig:
    return SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN, None),
        detection_compiler_timeout=2.0,
        detection_max_content_length=10000,
        detection_preserve_attack_patterns=True,
        detection_semantic_threshold=0.7,
        detection_anomaly_threshold=3.0,
        detection_slow_pattern_threshold=0.1,
        detection_monitor_history_size=1000,
        detection_max_tracked_patterns=1000,
    )


@pytest.fixture
def sus_patterns_manager_with_detection(
    security_config_with_detection: SecurityConfig,
) -> Generator[SusPatternsManager, None]:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config

    SusPatternsManager._instance = None
    SusPatternsManager._config = None

    manager = SusPatternsManager(security_config_with_detection)

    yield manager

    manager.reset()

    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config


@pytest.fixture(autouse=True)
def reset_sus_patterns() -> Generator[None, None]:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config

    original_patterns = None
    original_custom_patterns: set[str] = set()
    if original_instance:
        original_patterns = original_instance.patterns.copy()
        original_custom_patterns = original_instance.custom_patterns.copy()

    yield

    if SusPatternsManager._instance:
        SusPatternsManager._instance.reset()

    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config

    if original_instance and original_patterns:
        original_instance.patterns = original_patterns
        original_instance.custom_patterns = original_custom_patterns
