import logging
from collections.abc import Iterator

import pytest

from guard_core.sync.handlers import suspatterns_handler as sph
from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager


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


def _is_compiled_custom(manager: SusPatternsManager, pattern: str) -> bool:
    return any(
        p.pattern == pattern for p, _ctx, _cat in manager.compiled_custom_patterns
    )


def test_safe_pattern_is_added_to_custom_patterns(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    manager = fresh_legacy_singleton
    pattern = r"foo.*bar"

    manager.add_pattern(pattern, custom=True)

    assert pattern in manager.custom_patterns
    assert _is_compiled_custom(manager, pattern)


def test_catastrophic_pattern_is_rejected_with_warning_logged(
    fresh_legacy_singleton: SusPatternsManager,
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = fresh_legacy_singleton
    pattern = r"(a+)+$"

    with caplog.at_level(logging.WARNING):
        manager.add_pattern(pattern, custom=True)

    assert pattern not in manager.custom_patterns
    assert not _is_compiled_custom(manager, pattern)
    assert pattern[:50] in caplog.text


def test_malformed_pattern_is_rejected_without_raising(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    manager = fresh_legacy_singleton
    pattern = r"("

    manager.add_pattern(pattern, custom=True)

    assert pattern not in manager.custom_patterns
    assert not _is_compiled_custom(manager, pattern)


def test_legacy_mode_rejects_catastrophic_pattern_via_transient_compiler(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    manager = fresh_legacy_singleton
    assert manager._compiler is None
    pattern = r"(a+)+$"

    manager.add_pattern(pattern, custom=True)

    assert pattern not in manager.custom_patterns


def test_enhanced_mode_rejects_catastrophic_pattern_via_instance_compiler(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    manager = sus_patterns_manager_with_detection
    assert manager._compiler is not None
    pattern = r"(a+)+$"

    manager.add_pattern(pattern, custom=True)

    assert pattern not in manager.custom_patterns
