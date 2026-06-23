def test_async_route_config_block_cloud_providers_default() -> None:
    from guard_core.sync.decorators.base import RouteConfig

    rc = RouteConfig()
    assert rc.block_cloud_providers == set()


def test_sync_route_config_block_cloud_providers_default() -> None:
    from guard_core.sync.decorators.base import RouteConfig

    rc = RouteConfig()
    assert rc.block_cloud_providers == set()
