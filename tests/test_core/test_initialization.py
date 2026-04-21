from unittest.mock import AsyncMock, Mock, patch

import pytest

from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.models import SecurityConfig


@pytest.fixture
def security_config() -> SecurityConfig:
    config = SecurityConfig()
    config.enable_redis = True
    config.enable_agent = True
    config.enable_dynamic_rules = False
    config.block_cloud_providers = set()
    return config


@pytest.fixture
def mock_redis_handler() -> Mock:
    handler = Mock()
    handler.initialize = AsyncMock()
    handler.initialize_agent = AsyncMock()
    return handler


@pytest.fixture
def mock_agent_handler() -> Mock:
    handler = Mock()
    handler.start = AsyncMock()
    handler.initialize_redis = AsyncMock()
    return handler


@pytest.fixture
def mock_geo_ip_handler() -> Mock:
    handler = Mock()
    handler.initialize_redis = AsyncMock()
    handler.initialize_agent = AsyncMock()
    return handler


@pytest.fixture
def mock_rate_limit_handler() -> Mock:
    handler = Mock()
    handler.initialize_redis = AsyncMock()
    handler.initialize_agent = AsyncMock()
    return handler


@pytest.fixture
def mock_guard_decorator() -> Mock:
    decorator = Mock()
    decorator.initialize_agent = AsyncMock()
    return decorator


@pytest.fixture
def initializer(
    security_config: SecurityConfig,
    mock_redis_handler: Mock,
    mock_agent_handler: Mock,
    mock_geo_ip_handler: Mock,
    mock_rate_limit_handler: Mock,
    mock_guard_decorator: Mock,
) -> HandlerInitializer:
    return HandlerInitializer(
        config=security_config,
        redis_handler=mock_redis_handler,
        agent_handler=mock_agent_handler,
        geo_ip_handler=mock_geo_ip_handler,
        rate_limit_handler=mock_rate_limit_handler,
        guard_decorator=mock_guard_decorator,
    )


def test_init(
    initializer: HandlerInitializer,
    security_config: SecurityConfig,
    mock_redis_handler: Mock,
) -> None:
    assert initializer.config == security_config
    assert initializer.redis_handler == mock_redis_handler


async def test_initialize_redis_handlers_disabled(
    security_config: SecurityConfig,
) -> None:
    security_config.enable_redis = False
    initializer = HandlerInitializer(config=security_config)

    await initializer.initialize_redis_handlers()


async def test_initialize_redis_handlers_no_handler(
    security_config: SecurityConfig,
) -> None:
    initializer = HandlerInitializer(config=security_config, redis_handler=None)

    await initializer.initialize_redis_handlers()


async def test_initialize_redis_handlers_basic(
    initializer: HandlerInitializer,
    mock_redis_handler: Mock,
    mock_geo_ip_handler: Mock,
    mock_rate_limit_handler: Mock,
) -> None:
    with (
        patch("guard_core.handlers.cloud_handler.cloud_handler") as mock_cloud,
        patch("guard_core.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_cloud.initialize_redis = AsyncMock()
        mock_ipban.initialize_redis = AsyncMock()
        mock_sus.initialize_redis = AsyncMock()

        await initializer.initialize_redis_handlers()

        mock_redis_handler.initialize.assert_called_once()

        mock_ipban.initialize_redis.assert_called_once_with(mock_redis_handler)
        mock_geo_ip_handler.initialize_redis.assert_called_once_with(mock_redis_handler)
        mock_rate_limit_handler.initialize_redis.assert_called_once_with(
            mock_redis_handler
        )
        mock_sus.initialize_redis.assert_called_once_with(mock_redis_handler)


async def test_initialize_redis_handlers_with_cloud(
    initializer: HandlerInitializer,
    security_config: SecurityConfig,
    mock_redis_handler: Mock,
) -> None:
    security_config.block_cloud_providers = {"aws", "gcp"}

    with (
        patch("guard_core.handlers.cloud_handler.cloud_handler") as mock_cloud,
        patch("guard_core.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_cloud.initialize_redis = AsyncMock()
        mock_ipban.initialize_redis = AsyncMock()
        mock_sus.initialize_redis = AsyncMock()

        await initializer.initialize_redis_handlers()

        mock_cloud.initialize_redis.assert_called_once_with(
            mock_redis_handler,
            security_config.block_cloud_providers,
            ttl=security_config.cloud_ip_refresh_interval,
        )


async def test_initialize_redis_handlers_no_optional_handlers(
    security_config: SecurityConfig, mock_redis_handler: Mock
) -> None:
    initializer = HandlerInitializer(
        config=security_config,
        redis_handler=mock_redis_handler,
        geo_ip_handler=None,
        rate_limit_handler=None,
    )

    with (
        patch("guard_core.handlers.cloud_handler.cloud_handler") as mock_cloud,
        patch("guard_core.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_cloud.initialize_redis = AsyncMock()
        mock_ipban.initialize_redis = AsyncMock()
        mock_sus.initialize_redis = AsyncMock()

        await initializer.initialize_redis_handlers()

        mock_redis_handler.initialize.assert_called_once()


async def test_initialize_agent_for_handlers_no_agent(
    security_config: SecurityConfig,
) -> None:
    initializer = HandlerInitializer(config=security_config, agent_handler=None)

    await initializer.initialize_agent_for_handlers()


async def test_initialize_agent_for_handlers_basic(
    initializer: HandlerInitializer,
    mock_agent_handler: Mock,
    mock_rate_limit_handler: Mock,
) -> None:
    with (
        patch("guard_core.handlers.cloud_handler.cloud_handler") as mock_cloud,
        patch("guard_core.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_cloud.initialize_agent = AsyncMock()
        mock_ipban.initialize_agent = AsyncMock()
        mock_sus.initialize_agent = AsyncMock()

        await initializer.initialize_agent_for_handlers()

        mock_ipban.initialize_agent.assert_called_once_with(mock_agent_handler)
        mock_rate_limit_handler.initialize_agent.assert_called_once_with(
            mock_agent_handler
        )
        mock_sus.initialize_agent.assert_called_once_with(mock_agent_handler)


async def test_initialize_agent_for_handlers_with_cloud(
    initializer: HandlerInitializer,
    security_config: SecurityConfig,
    mock_agent_handler: Mock,
) -> None:
    security_config.block_cloud_providers = {"aws"}

    with (
        patch("guard_core.handlers.cloud_handler.cloud_handler") as mock_cloud,
        patch("guard_core.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_cloud.initialize_agent = AsyncMock()
        mock_ipban.initialize_agent = AsyncMock()
        mock_sus.initialize_agent = AsyncMock()

        await initializer.initialize_agent_for_handlers()

        mock_cloud.initialize_agent.assert_called_once_with(mock_agent_handler)


async def test_initialize_agent_for_handlers_without_rate_limit(
    security_config: SecurityConfig,
    mock_agent_handler: Mock,
) -> None:
    initializer = HandlerInitializer(
        config=security_config,
        agent_handler=mock_agent_handler,
        rate_limit_handler=None,
    )
    with (
        patch("guard_core.handlers.cloud_handler.cloud_handler") as mock_cloud,
        patch("guard_core.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_cloud.initialize_agent = AsyncMock()
        mock_ipban.initialize_agent = AsyncMock()
        mock_sus.initialize_agent = AsyncMock()

        await initializer.initialize_agent_for_handlers()


async def test_initialize_agent_for_handlers_geoip_without_method(
    security_config: SecurityConfig,
    mock_agent_handler: Mock,
) -> None:
    geo = Mock(spec=[])
    initializer = HandlerInitializer(
        config=security_config,
        agent_handler=mock_agent_handler,
        geo_ip_handler=geo,
    )
    with (
        patch("guard_core.handlers.cloud_handler.cloud_handler") as mock_cloud,
        patch("guard_core.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_cloud.initialize_agent = AsyncMock()
        mock_ipban.initialize_agent = AsyncMock()
        mock_sus.initialize_agent = AsyncMock()

        await initializer.initialize_agent_for_handlers()


async def test_initialize_agent_for_handlers_with_geoip(
    initializer: HandlerInitializer,
    mock_agent_handler: Mock,
    mock_geo_ip_handler: Mock,
) -> None:
    with (
        patch("guard_core.handlers.cloud_handler.cloud_handler") as mock_cloud,
        patch("guard_core.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_cloud.initialize_agent = AsyncMock()
        mock_ipban.initialize_agent = AsyncMock()
        mock_sus.initialize_agent = AsyncMock()

        await initializer.initialize_agent_for_handlers()

        mock_geo_ip_handler.initialize_agent.assert_called_once_with(mock_agent_handler)


async def test_initialize_dynamic_rule_manager_disabled(
    security_config: SecurityConfig,
) -> None:
    initializer = HandlerInitializer(config=security_config)

    await initializer.initialize_dynamic_rule_manager()


async def test_initialize_dynamic_rule_manager_no_agent(
    security_config: SecurityConfig,
) -> None:
    security_config.enable_dynamic_rules = True
    initializer = HandlerInitializer(config=security_config, agent_handler=None)

    await initializer.initialize_dynamic_rule_manager()


async def test_initialize_dynamic_rule_manager_enabled(
    initializer: HandlerInitializer,
    security_config: SecurityConfig,
    mock_agent_handler: Mock,
    mock_redis_handler: Mock,
) -> None:
    security_config.enable_dynamic_rules = True

    with patch(
        "guard_core.handlers.dynamic_rule_handler.DynamicRuleManager"
    ) as MockDRM:
        mock_drm_instance = Mock()
        mock_drm_instance.initialize_agent = AsyncMock()
        mock_drm_instance.initialize_redis = AsyncMock()
        MockDRM.return_value = mock_drm_instance

        await initializer.initialize_dynamic_rule_manager()

        MockDRM.assert_called_once_with(security_config)
        mock_drm_instance.initialize_agent.assert_called_once_with(mock_agent_handler)
        mock_drm_instance.initialize_redis.assert_called_once_with(mock_redis_handler)


async def test_initialize_dynamic_rule_manager_no_redis(
    security_config: SecurityConfig, mock_agent_handler: Mock
) -> None:
    security_config.enable_dynamic_rules = True
    initializer = HandlerInitializer(
        config=security_config,
        agent_handler=mock_agent_handler,
        redis_handler=None,
    )

    with patch(
        "guard_core.handlers.dynamic_rule_handler.DynamicRuleManager"
    ) as MockDRM:
        mock_drm_instance = Mock()
        mock_drm_instance.initialize_agent = AsyncMock()
        mock_drm_instance.initialize_redis = AsyncMock()
        MockDRM.return_value = mock_drm_instance

        await initializer.initialize_dynamic_rule_manager()

        mock_drm_instance.initialize_redis.assert_not_called()


async def test_initialize_agent_integrations_no_agent(
    security_config: SecurityConfig,
) -> None:
    initializer = HandlerInitializer(config=security_config, agent_handler=None)

    await initializer.initialize_agent_integrations()


async def test_initialize_agent_integrations_full(
    initializer: HandlerInitializer,
    mock_agent_handler: Mock,
    mock_redis_handler: Mock,
    mock_guard_decorator: Mock,
) -> None:
    mock_init_handlers = AsyncMock()
    mock_init_drm = AsyncMock()
    with (
        patch.object(initializer, "initialize_agent_for_handlers", mock_init_handlers),
        patch.object(initializer, "initialize_dynamic_rule_manager", mock_init_drm),
    ):
        await initializer.initialize_agent_integrations()

        mock_agent_handler.start.assert_called_once()

        mock_agent_handler.initialize_redis.assert_called_once_with(mock_redis_handler)
        mock_redis_handler.initialize_agent.assert_called_once_with(mock_agent_handler)

        mock_init_handlers.assert_called_once()

        mock_guard_decorator.initialize_agent.assert_called_once_with(
            mock_agent_handler
        )

        mock_init_drm.assert_called_once()


async def test_initialize_agent_integrations_no_redis(
    security_config: SecurityConfig, mock_agent_handler: Mock
) -> None:
    initializer = HandlerInitializer(
        config=security_config,
        agent_handler=mock_agent_handler,
        redis_handler=None,
    )

    with (
        patch.object(initializer, "initialize_agent_for_handlers", AsyncMock()),
        patch.object(initializer, "initialize_dynamic_rule_manager", AsyncMock()),
    ):
        await initializer.initialize_agent_integrations()

        mock_agent_handler.initialize_redis.assert_not_called()


async def test_initialize_agent_integrations_no_decorator(
    security_config: SecurityConfig, mock_agent_handler: Mock
) -> None:
    initializer = HandlerInitializer(
        config=security_config,
        agent_handler=mock_agent_handler,
        guard_decorator=None,
    )

    with (
        patch.object(initializer, "initialize_agent_for_handlers", AsyncMock()),
        patch.object(initializer, "initialize_dynamic_rule_manager", AsyncMock()),
    ):
        await initializer.initialize_agent_integrations()

        mock_agent_handler.start.assert_called_once()


async def test_initialize_agent_integrations_decorator_no_method(
    security_config: SecurityConfig, mock_agent_handler: Mock
) -> None:
    decorator_no_method = Mock(spec=[])
    initializer = HandlerInitializer(
        config=security_config,
        agent_handler=mock_agent_handler,
        guard_decorator=decorator_no_method,
    )

    with (
        patch.object(initializer, "initialize_agent_for_handlers", AsyncMock()),
        patch.object(initializer, "initialize_dynamic_rule_manager", AsyncMock()),
    ):
        await initializer.initialize_agent_integrations()

        mock_agent_handler.start.assert_called_once()
