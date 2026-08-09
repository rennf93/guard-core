import logging
from ipaddress import ip_network
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.core.checks import factory
from guard_core.core.checks.factory import build_default_pipeline
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.core.routing.context import RoutingContext
from guard_core.core.routing.resolver import RouteConfigResolver
from guard_core.handlers.cloud_handler import cloud_handler
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest, MockGuardResponse

_LOGGER = logging.getLogger("test_pipeline_config_revision")


async def _blocking_custom_request_check(request: object) -> MockGuardResponse:
    return MockGuardResponse("blocked-by-custom-request-check", 451)


def _neutral_config(**overrides: object) -> SecurityConfig:
    fields: dict[str, object] = {
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
    }
    fields.update(overrides)
    return SecurityConfig(**fields)


def _build_middleware(config: SecurityConfig) -> MagicMock:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = _LOGGER
    middleware.event_bus = MagicMock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.event_bus.send_cloud_detection_events = AsyncMock()
    middleware.create_error_response = AsyncMock(
        side_effect=lambda status_code, default_message: MockGuardResponse(
            default_message, status_code
        )
    )
    middleware.response_factory = MagicMock()
    middleware.response_factory.apply_modifier = AsyncMock(side_effect=lambda r: r)
    decorator = MagicMock()
    decorator._route_configs = {}
    middleware.guard_decorator = decorator
    middleware.route_resolver = RouteConfigResolver(
        RoutingContext(config=config, logger=_LOGGER, guard_decorator=decorator)
    )
    middleware.geo_ip_handler = None
    middleware.agent_handler = None
    middleware.last_cloud_ip_refresh = 0
    middleware.refresh_cloud_ip_ranges = AsyncMock()
    middleware.rate_limit_handler = MagicMock()
    middleware.rate_limit_handler.check_rate_limit = AsyncMock(return_value=None)
    return middleware


async def test_mutating_config_makes_eliminated_user_agent_check_block() -> None:
    config = _neutral_config()
    middleware = _build_middleware(config)
    pipeline = build_default_pipeline(middleware)
    assert "user_agent" not in pipeline.get_check_names()

    config.blocked_user_agents = ["badbot"]

    request = MockGuardRequest(
        client_host="198.51.100.101",
        headers={"User-Agent": "badbot-scanner"},
    )
    result = await pipeline.execute(request)

    assert "user_agent" in pipeline.get_check_names()
    assert result is not None
    assert result.status_code == 403


async def test_mutating_config_makes_eliminated_cloud_provider_check_block() -> None:
    config = _neutral_config()
    middleware = _build_middleware(config)
    pipeline = build_default_pipeline(middleware)
    assert "cloud_provider" not in pipeline.get_check_names()

    cloud_handler.ip_ranges["AWS"].add(ip_network("3.0.0.0/8"))
    config.block_cloud_providers = {"AWS"}

    request = MockGuardRequest(client_host="3.0.0.9")
    with patch.object(cloud_handler, "schedule_refresh", AsyncMock(return_value=False)):
        result = await pipeline.execute(request)

    assert "cloud_provider" in pipeline.get_check_names()
    assert result is not None
    assert result.status_code == 403


async def test_mutating_config_makes_eliminated_custom_request_check_block() -> None:
    config = _neutral_config()
    middleware = _build_middleware(config)
    pipeline = build_default_pipeline(middleware)
    assert "custom_request" not in pipeline.get_check_names()

    config.custom_request_check = cast(Any, _blocking_custom_request_check)

    request = MockGuardRequest(client_host="198.51.100.102")
    result = await pipeline.execute(request)

    assert "custom_request" in pipeline.get_check_names()
    assert result is not None
    assert result.status_code == 451


async def test_mutating_a_field_no_predicate_reads_does_not_change_composition() -> (
    None
):
    config = _neutral_config()
    middleware = _build_middleware(config)

    with patch.object(
        factory, "_build_checks", wraps=factory._build_checks
    ) as rebuild_spy:
        pipeline = build_default_pipeline(middleware)
        before = pipeline.get_check_names()
        rebuild_spy.reset_mock()

        config.custom_log_file = "new-location.log"

        request = MockGuardRequest(client_host="198.51.100.103")
        for _ in range(5):
            await pipeline.execute(request)

        assert pipeline.get_check_names() == before
        assert rebuild_spy.call_count == 1


async def test_execute_does_not_rebuild_when_config_is_unchanged() -> None:
    config = _neutral_config()
    middleware = _build_middleware(config)

    with patch.object(
        factory, "_build_checks", wraps=factory._build_checks
    ) as rebuild_spy:
        pipeline = build_default_pipeline(middleware)
        rebuild_spy.reset_mock()

        request = MockGuardRequest(client_host="198.51.100.104")
        for _ in range(5):
            await pipeline.execute(request)

        rebuild_spy.assert_not_called()


async def test_rebuild_swaps_checks_via_new_list_not_in_place_mutation() -> None:
    config = _neutral_config()
    middleware = _build_middleware(config)
    pipeline = build_default_pipeline(middleware)

    snapshot = pipeline.checks
    snapshot_names_before = [check.check_name for check in snapshot]

    config.blocked_user_agents = ["badbot"]
    request = MockGuardRequest(client_host="198.51.100.105")
    await pipeline.execute(request)

    assert pipeline.checks is not snapshot
    assert [check.check_name for check in snapshot] == snapshot_names_before


async def test_pipeline_built_without_config_never_rebuilds() -> None:
    config = _neutral_config()
    middleware = _build_middleware(config)
    checks = factory._build_checks(middleware)

    pipeline = SecurityCheckPipeline(checks)
    original_checks = pipeline.checks

    config.blocked_user_agents = ["badbot"]
    request = MockGuardRequest(
        client_host="198.51.100.106",
        headers={"User-Agent": "badbot-scanner"},
    )
    result = await pipeline.execute(request)

    assert pipeline.checks is original_checks
    assert result is None


async def test_appending_blocked_user_agent_in_place_runs_eliminated_check() -> None:
    config = _neutral_config()
    middleware = _build_middleware(config)
    pipeline = build_default_pipeline(middleware)
    assert "user_agent" not in pipeline.get_check_names()

    config.blocked_user_agents.append("badbot")

    request = MockGuardRequest(
        client_host="198.51.100.121",
        headers={"User-Agent": "badbot-scanner"},
    )
    result = await pipeline.execute(request)

    assert "user_agent" in pipeline.get_check_names()
    assert result is not None
    assert result.status_code == 403


async def test_replacing_blocked_user_agent_in_place_does_not_rebuild() -> None:
    config = _neutral_config(blocked_user_agents=["goodbot"])
    middleware = _build_middleware(config)

    with patch.object(
        factory, "_build_checks", wraps=factory._build_checks
    ) as rebuild_spy:
        pipeline = build_default_pipeline(middleware)
        assert "user_agent" in pipeline.get_check_names()
        rebuild_spy.reset_mock()

        config.blocked_user_agents[0] = "otherbot"

        request = MockGuardRequest(
            client_host="198.51.100.122",
            headers={"User-Agent": "harmless"},
        )
        for _ in range(5):
            await pipeline.execute(request)

        rebuild_spy.assert_not_called()


async def test_adding_block_cloud_provider_in_place_runs_eliminated_check() -> None:
    config = _neutral_config(block_cloud_providers=set())
    middleware = _build_middleware(config)
    pipeline = build_default_pipeline(middleware)
    assert "cloud_provider" not in pipeline.get_check_names()

    cloud_handler.ip_ranges["AWS"].add(ip_network("4.0.0.0/8"))
    assert config.block_cloud_providers is not None
    config.block_cloud_providers.add("AWS")

    request = MockGuardRequest(client_host="4.0.0.9")
    with patch.object(cloud_handler, "schedule_refresh", AsyncMock(return_value=False)):
        result = await pipeline.execute(request)

    assert "cloud_provider" in pipeline.get_check_names()
    assert result is not None
    assert result.status_code == 403


async def test_swapping_block_cloud_provider_in_place_does_not_rebuild() -> None:
    config = _neutral_config(block_cloud_providers={"AWS"})
    middleware = _build_middleware(config)

    with patch.object(
        factory, "_build_checks", wraps=factory._build_checks
    ) as rebuild_spy:
        pipeline = build_default_pipeline(middleware)
        assert "cloud_provider" in pipeline.get_check_names()
        rebuild_spy.reset_mock()

        assert config.block_cloud_providers is not None
        config.block_cloud_providers.symmetric_difference_update({"AWS", "GCP"})

        request = MockGuardRequest(client_host="198.51.100.123")
        with patch.object(
            cloud_handler, "schedule_refresh", AsyncMock(return_value=False)
        ):
            for _ in range(5):
                await pipeline.execute(request)

        rebuild_spy.assert_not_called()


async def test_setting_an_endpoint_rate_limit_in_place_makes_eliminated_check_run() -> (
    None
):
    config = _neutral_config()
    middleware = _build_middleware(config)
    pipeline = build_default_pipeline(middleware)
    assert "rate_limit" not in pipeline.get_check_names()

    config.endpoint_rate_limits["/x"] = (0, 60)

    request = MockGuardRequest(client_host="198.51.100.124", path="/x")
    await pipeline.execute(request)

    assert "rate_limit" in pipeline.get_check_names()


async def test_overwriting_an_endpoint_rate_limit_value_in_place_does_not_rebuild() -> (
    None
):
    config = _neutral_config(endpoint_rate_limits={"/x": (5, 60)})
    middleware = _build_middleware(config)

    with patch.object(
        factory, "_build_checks", wraps=factory._build_checks
    ) as rebuild_spy:
        pipeline = build_default_pipeline(middleware)
        assert "rate_limit" in pipeline.get_check_names()
        rebuild_spy.reset_mock()

        config.endpoint_rate_limits["/x"] = (1, 30)

        request = MockGuardRequest(client_host="198.51.100.125", path="/x")
        for _ in range(5):
            await pipeline.execute(request)

        rebuild_spy.assert_not_called()


@pytest.mark.parametrize("field_name", ["blacklist", "whitelist"])
def test_mutating_blacklist_or_whitelist_in_place_never_flips_any_check_applies_to(
    field_name: str,
) -> None:
    assert field_name not in factory.WATCHED_CONTAINER_FIELDS

    config = SecurityConfig(**{field_name: []})
    before = {
        cls: cls.applies_to(config, None) for cls in factory.DEFAULT_CHECK_CLASSES
    }

    getattr(config, field_name).append("203.0.113.5")

    after = {cls: cls.applies_to(config, None) for cls in factory.DEFAULT_CHECK_CLASSES}

    assert before == after
