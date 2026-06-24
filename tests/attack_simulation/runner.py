from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from guard_core.handlers.suspatterns_handler import SusPatternsManager
from guard_core.models import SecurityConfig

SCAN_IP = "203.0.113.1"


def build_detection_config() -> SecurityConfig:
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


@asynccontextmanager
async def detection_manager(
    config: SecurityConfig | None = None,
) -> AsyncIterator[SusPatternsManager]:
    config = config or build_detection_config()
    saved_instance = SusPatternsManager._instance
    saved_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    manager = SusPatternsManager(config)
    try:
        yield manager
    finally:
        await manager.reset()
        SusPatternsManager._instance = saved_instance
        SusPatternsManager._config = saved_config


async def scan(
    manager: SusPatternsManager, payload: str, *, context: str = "unknown"
) -> bool:
    result = await manager.detect(payload, ip_address=SCAN_IP, context=context)
    return bool(result["is_threat"])
