import uuid
from collections.abc import AsyncGenerator
from pathlib import Path

import pytest

from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL

_CLOUD_IP_REDIS_PREFIX = f"test:guard_core_cloud_ip_isolation:{uuid.uuid4().hex}:"


@pytest.fixture
def security_config_redis(ipinfo_db_path: Path) -> SecurityConfig:
    return SecurityConfig(
        redis_url=REDIS_URL,
        redis_prefix=_CLOUD_IP_REDIS_PREFIX,
        whitelist=["127.0.0.1"],
        blacklist=["192.168.1.1"],
        blocked_user_agents=[r"badbot"],
        auto_ban_threshold=3,
        auto_ban_duration=300,
        custom_log_file="test_log.log",
        custom_error_responses={
            403: "Custom Forbidden",
            429: "Custom Too Many Requests",
        },
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["*"],
        cors_allow_credentials=True,
        cors_expose_headers=["X-Custom-Header"],
        cors_max_age=600,
    )


async def _flush_cloud_ip_redis_namespace() -> None:
    config = SecurityConfig(redis_url=REDIS_URL, redis_prefix=_CLOUD_IP_REDIS_PREFIX)
    redis_handler = RedisManager(config)
    await redis_handler.initialize()
    try:
        await redis_handler.delete_pattern("*")
    except Exception:
        pass
    finally:
        await redis_handler.close()


@pytest.fixture(autouse=True)
async def cloud_ip_redis_isolation() -> AsyncGenerator[None, None]:
    await _flush_cloud_ip_redis_namespace()
    yield
    await _flush_cloud_ip_redis_namespace()
