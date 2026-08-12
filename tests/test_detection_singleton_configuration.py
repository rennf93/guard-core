from collections.abc import Iterator

import pytest

from guard_core.core.initialization import HandlerInitializer
from guard_core.handlers import suspatterns_handler as sph
from guard_core.handlers.suspatterns_handler import SusPatternsManager
from guard_core.models import SecurityConfig


@pytest.fixture
def fresh_legacy_singleton() -> Iterator[SusPatternsManager]:
    saved_instance = SusPatternsManager._instance
    saved_config = SusPatternsManager._config
    saved_global = sph.sus_patterns_handler

    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    legacy = SusPatternsManager()
    sph.sus_patterns_handler = legacy

    yield legacy

    SusPatternsManager._instance = saved_instance
    SusPatternsManager._config = saved_config
    sph.sus_patterns_handler = saved_global


async def test_initialize_configures_detection_from_config(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    handler = fresh_legacy_singleton
    assert handler._threat_score_threshold == 1.0
    compiler_before = handler._compiler
    assert compiler_before is None

    config = SecurityConfig(detection_threat_score_threshold=2.5)
    initializer = HandlerInitializer(config=config)
    await initializer.initialize_redis_handlers()

    assert handler._threat_score_threshold == 2.5
    assert handler._semantic_threshold == config.detection_semantic_threshold
    assert handler._compiler is not None
    assert handler._preprocessor is not None
    assert handler._semantic_analyzer is not None


def test_configure_applies_enhanced_config(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    handler = fresh_legacy_singleton
    config = SecurityConfig(detection_threat_score_threshold=3.0)

    handler.configure(config)

    assert handler._threat_score_threshold == 3.0
    assert handler._compiler is not None


def test_configure_ignores_none(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    handler = fresh_legacy_singleton

    handler.configure(None)

    assert handler._threat_score_threshold == 1.0
    assert handler._compiler is None


def test_configure_ignores_object_without_detection_fields(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    handler = fresh_legacy_singleton

    handler.configure(object())

    assert handler._threat_score_threshold == 1.0
    assert handler._compiler is None


def test_configure_ignores_config_missing_new_detection_fields(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    handler = fresh_legacy_singleton

    class PartialConfig:
        detection_compiler_timeout = 3.0
        detection_max_tracked_patterns = 500
        detection_max_content_length = 20000
        detection_preserve_attack_patterns = True
        detection_anomaly_threshold = 2.5
        detection_slow_pattern_threshold = 0.2
        detection_monitor_history_size = 100
        detection_semantic_threshold = 0.8
        detection_threat_score_threshold = 1.0

    handler.configure(PartialConfig())

    assert handler._threat_score_threshold == 1.0
    assert handler._compiler is None
