from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock, patch

from guard_core.models import SecurityConfig
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer


def _make_initializer(
    lazy_init: bool, block_cloud: set[str] | None = None
) -> tuple[HandlerInitializer, MagicMock, MagicMock]:
    config = SecurityConfig(
        lazy_init=lazy_init,
        enable_redis=True,
        block_cloud_providers=block_cloud or set(),
    )
    redis_handler = MagicMock()
    redis_handler.initialize = MagicMock()
    redis_handler.initialize_agent = MagicMock()
    geo_ip = MagicMock()
    geo_ip.initialize_redis = MagicMock()
    rate_limit = MagicMock()
    rate_limit.initialize_redis = MagicMock()
    return (
        HandlerInitializer(
            config=config,
            redis_handler=redis_handler,
            geo_ip_handler=geo_ip,
            rate_limit_handler=rate_limit,
        ),
        geo_ip,
        redis_handler,
    )


@contextmanager
def _patch_handlers() -> Any:
    with (
        patch("guard_core.sync.handlers.cloud_handler.cloud_handler") as cloud,
        patch("guard_core.sync.handlers.ipban_handler.ip_ban_manager") as ipban,
        patch(
            "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
        ) as sus,
    ):
        cloud.initialize_redis = MagicMock()
        ipban.initialize_redis = MagicMock()
        sus.initialize_redis = MagicMock()
        yield {"cloud": cloud, "ipban": ipban, "suspatterns": sus}


def test_eager_init_runs_geo_and_cloud() -> None:
    initializer, geo_ip, _ = _make_initializer(lazy_init=False, block_cloud={"AWS"})
    with _patch_handlers() as patches:
        initializer.initialize_redis_handlers()
        patches["cloud"].initialize_redis.assert_called_once()
    geo_ip.initialize_redis.assert_called_once()


def test_lazy_init_skips_geo_and_cloud() -> None:
    initializer, geo_ip, _ = _make_initializer(lazy_init=True, block_cloud={"AWS"})
    with _patch_handlers() as patches:
        initializer.initialize_redis_handlers()
        patches["cloud"].initialize_redis.assert_not_called()
    geo_ip.initialize_redis.assert_not_called()


def test_lazy_init_still_initializes_ipban_and_suspatterns() -> None:
    initializer, _, _ = _make_initializer(lazy_init=True)
    with _patch_handlers() as patches:
        initializer.initialize_redis_handlers()
        patches["ipban"].initialize_redis.assert_called_once()
        patches["suspatterns"].initialize_redis.assert_called_once()


def test_lazy_init_with_empty_cloud_providers_skips_cloud() -> None:
    initializer, _, _ = _make_initializer(lazy_init=False, block_cloud=None)
    with _patch_handlers() as patches:
        initializer.initialize_redis_handlers()
        patches["cloud"].initialize_redis.assert_not_called()


def test_no_redis_handler_returns_immediately() -> None:
    config = SecurityConfig(lazy_init=False, enable_redis=True)
    initializer = HandlerInitializer(config=config, redis_handler=None)
    initializer.initialize_redis_handlers()
