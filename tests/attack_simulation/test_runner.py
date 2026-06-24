import pytest

from guard_core.handlers.suspatterns_handler import SusPatternsManager
from tests.attack_simulation.runner import (
    build_detection_config,
    detection_manager,
    scan,
)


def test_build_detection_config_activates_preprocessor():
    config = build_detection_config()
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    manager = SusPatternsManager(config)
    assert manager._preprocessor is not None
    SusPatternsManager._instance = None
    SusPatternsManager._config = None


@pytest.mark.asyncio
async def test_scan_detects_raw_attack_and_passes_benign():
    async with detection_manager() as manager:
        assert await scan(manager, "<script>alert(1)</script>") is True
        assert await scan(manager, "the quick brown fox jumps over") is False


@pytest.mark.asyncio
async def test_detection_manager_restores_singleton():
    sentinel = object()
    SusPatternsManager._instance = sentinel
    async with detection_manager() as manager:
        assert manager is not sentinel
    assert SusPatternsManager._instance is sentinel
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
