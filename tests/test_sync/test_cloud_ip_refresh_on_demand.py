import ipaddress
from unittest.mock import MagicMock, patch

from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.implementations.cloud_ip_refresh import (
    CloudIpRefreshCheck,
)
from guard_core.sync.handlers.cloud_handler import cloud_handler


def test_lazy_init_triggers_initial_refresh_when_ranges_empty() -> None:
    config = SecurityConfig(lazy_init=True, block_cloud_providers={"AWS"})
    middleware = MagicMock()
    middleware.config = config
    middleware.last_cloud_ip_refresh = 0
    middleware.refresh_cloud_ip_ranges = MagicMock()

    cloud_handler.ip_ranges["AWS"] = set()

    check = CloudIpRefreshCheck(middleware)
    with patch.object(cloud_handler, "refresh_async", new=MagicMock()) as mock_refresh:
        check.check(MagicMock())
        mock_refresh.assert_called_once()


def test_eager_init_does_not_trigger_on_demand_refresh() -> None:
    config = SecurityConfig(lazy_init=False, block_cloud_providers={"AWS"})
    middleware = MagicMock()
    middleware.config = config
    middleware.last_cloud_ip_refresh = 9999999999
    middleware.refresh_cloud_ip_ranges = MagicMock()

    cloud_handler.ip_ranges["AWS"] = {ipaddress.ip_network("10.0.0.0/8")}

    check = CloudIpRefreshCheck(middleware)
    with patch.object(cloud_handler, "refresh_async", new=MagicMock()) as mock_refresh:
        check.check(MagicMock())
        mock_refresh.assert_not_called()


def test_scheduled_refresh_still_fires_when_interval_elapsed() -> None:
    config = SecurityConfig(
        lazy_init=False,
        block_cloud_providers={"AWS"},
        cloud_ip_refresh_interval=60,
    )
    middleware = MagicMock()
    middleware.config = config
    middleware.last_cloud_ip_refresh = 0
    middleware.refresh_cloud_ip_ranges = MagicMock()

    check = CloudIpRefreshCheck(middleware)
    check.check(MagicMock())
    middleware.refresh_cloud_ip_ranges.assert_called_once()


def test_lazy_init_with_empty_block_cloud_returns_immediately() -> None:
    config = SecurityConfig(lazy_init=True, block_cloud_providers=None)
    middleware = MagicMock()
    middleware.config = config
    middleware.last_cloud_ip_refresh = 0
    middleware.refresh_cloud_ip_ranges = MagicMock()

    check = CloudIpRefreshCheck(middleware)
    with patch.object(cloud_handler, "refresh_async", new=MagicMock()) as mock_refresh:
        result = check.check(MagicMock())
        mock_refresh.assert_not_called()
    assert result is None
    middleware.refresh_cloud_ip_ranges.assert_not_called()


def test_lazy_init_skips_refresh_when_ranges_already_populated() -> None:
    config = SecurityConfig(
        lazy_init=True,
        block_cloud_providers={"AWS"},
        cloud_ip_refresh_interval=300,
    )
    middleware = MagicMock()
    middleware.config = config
    middleware.last_cloud_ip_refresh = 9999999999
    middleware.refresh_cloud_ip_ranges = MagicMock()

    cloud_handler.ip_ranges["AWS"] = {ipaddress.ip_network("10.0.0.0/8")}

    check = CloudIpRefreshCheck(middleware)
    with patch.object(cloud_handler, "refresh_async", new=MagicMock()) as mock_refresh:
        check.check(MagicMock())
        mock_refresh.assert_not_called()
    middleware.refresh_cloud_ip_ranges.assert_not_called()


def test_handler_initializer_wires_user_supplied_store() -> None:
    from guard_core.sync.core.initialization.handler_initializer import (
        HandlerInitializer,
    )
    from guard_core.sync.handlers.cloud_ip_stores import InMemoryCloudIpStore

    custom_store = InMemoryCloudIpStore()
    config = SecurityConfig(
        enable_redis=True,
        block_cloud_providers={"AWS"},
        cloud_ip_store=custom_store,
    )
    redis_handler = MagicMock()
    redis_handler.initialize = MagicMock()
    initializer = HandlerInitializer(
        config=config,
        redis_handler=redis_handler,
    )

    with (
        patch("guard_core.sync.handlers.cloud_handler.cloud_handler") as cloud,
        patch("guard_core.sync.handlers.ipban_handler.ip_ban_manager") as ipban,
        patch(
            "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
        ) as sus,
    ):
        cloud.initialize_redis = MagicMock()
        cloud.set_store = MagicMock()
        ipban.initialize_redis = MagicMock()
        sus.initialize_redis = MagicMock()
        initializer.initialize_redis_handlers()
        cloud.set_store.assert_called_once_with(custom_store)
