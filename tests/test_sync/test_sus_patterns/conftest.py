from collections.abc import Callable, Generator
from contextlib import contextmanager
from pathlib import Path

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager

_THIS_DIR = Path(__file__).parent


def _detection_security_config() -> SecurityConfig:
    return SecurityConfig(
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
def security_config_with_detection() -> SecurityConfig:
    return _detection_security_config()


@contextmanager
def sus_patterns_manager_with_detection_ctx() -> Generator[SusPatternsManager, None]:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config

    SusPatternsManager._instance = None
    SusPatternsManager._config = None

    manager = SusPatternsManager(_detection_security_config())

    try:
        yield manager
    finally:
        manager.reset()
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config


@pytest.fixture
def sus_patterns_manager_with_detection(
    security_config_with_detection: SecurityConfig,
) -> Generator[SusPatternsManager, None]:
    with sus_patterns_manager_with_detection_ctx() as manager:
        yield manager


def with_detection_manager(
    func: Callable[[SusPatternsManager], None],
) -> Callable[[], None]:
    def wrapper() -> None:
        with sus_patterns_manager_with_detection_ctx() as manager:
            func(manager)

    wrapper.__name__ = func.__name__
    return wrapper


_SusPatternsSnapshot = tuple[
    SusPatternsManager | None, SecurityConfig | None, list[str] | None, set[str]
]


def _snapshot_sus_patterns() -> _SusPatternsSnapshot:
    instance = SusPatternsManager._instance
    config = SusPatternsManager._config
    patterns = instance.patterns.copy() if instance else None
    custom_patterns = instance.custom_patterns.copy() if instance else set()
    return instance, config, patterns, custom_patterns


_sus_patterns_snapshots: dict[int, _SusPatternsSnapshot] = {}


def pytest_runtest_setup(item: pytest.Item) -> None:
    """Runs before any fixture setup for the item: pluggy calls this
    conftest-registered hookimpl before the earlier-registered core
    _pytest.runner hookimpl that triggers fixture setup."""
    if item.path.parent != _THIS_DIR:
        return
    _sus_patterns_snapshots[id(item)] = _snapshot_sus_patterns()


def pytest_runtest_teardown(item: pytest.Item) -> None:
    """Runs before any fixture finalizer for the item, for the same LIFO
    reason as pytest_runtest_setup above: this hookimpl runs before the
    core _pytest.runner hookimpl that triggers fixture teardown."""
    snapshot = _sus_patterns_snapshots.pop(id(item), None)
    if snapshot is None:
        return
    original_instance, original_config, original_patterns, original_custom_patterns = (
        snapshot
    )

    if SusPatternsManager._instance:
        SusPatternsManager._instance.reset()

    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config

    if original_instance and original_patterns is not None:
        original_instance.patterns = original_patterns
        original_instance.custom_patterns = original_custom_patterns
