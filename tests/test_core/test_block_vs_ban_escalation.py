from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.core.checks.implementations.ip_security import IpSecurityCheck
from guard_core.core.checks.implementations.user_agent import UserAgentCheck
from guard_core.detection_result import DetectionResult
from guard_core.models import SecurityConfig
from guard_core.utils import IpAccessResult


def _make_middleware(config: SecurityConfig) -> MagicMock:
    mw = MagicMock()
    mw.config = config
    mw.logger = MagicMock()
    mw.event_bus = MagicMock()
    mw.event_bus.send_middleware_event = AsyncMock()
    mw.create_error_response = AsyncMock(return_value=MagicMock(status_code=403))
    mw.route_resolver = MagicMock()
    mw.route_resolver.should_bypass_check = MagicMock(return_value=False)
    mw.geo_ip_handler = None
    mw.suspicious_request_counts = {}
    return mw


def _make_request(client_ip: str | None = "1.2.3.4") -> MagicMock:
    request = MagicMock()
    request.state = MagicMock()
    request.state.client_ip = client_ip
    request.state.route_config = None
    request.state.is_whitelisted = False
    request.headers = {"User-Agent": "badbot"}
    return request


def _patch_detect_threat(
    monkeypatch: pytest.MonkeyPatch,
    is_threat: bool = True,
    trigger_info: str = "xss hit",
    threat_categories: list[str] | None = None,
) -> None:
    async def fake_detect(*_args: Any, **_kwargs: Any) -> DetectionResult:
        return DetectionResult(
            is_threat=is_threat,
            trigger_info=trigger_info,
            threat_categories=threat_categories
            if threat_categories is not None
            else ["xss"],
        )

    monkeypatch.setattr(
        "guard_core.core.checks.helpers.detect_penetration_patterns", fake_detect
    )


async def test_global_ip_block_with_threat_increments_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False, enable_ip_banning=True, auto_ban_threshold=1000
    )
    mw = _make_middleware(config)
    check = IpSecurityCheck(mw)
    request = _make_request("20.0.0.1")
    ban = AsyncMock()
    check.ip_ban_manager = ban

    with (
        patch(
            "guard_core.core.checks.implementations.ip_security.check_ip_access",
            new_callable=AsyncMock,
            return_value=IpAccessResult(False, "blocked"),
        ),
        patch("guard_core.core.checks.implementations.ip_security.log_activity"),
    ):
        _patch_detect_threat(monkeypatch)
        result = await check._check_global_ip_restrictions(request, "20.0.0.1")

    assert result is not None
    assert mw.suspicious_request_counts["20.0.0.1"] == {"xss": 1}
    ban.ban_ip.assert_not_called()


async def test_global_ip_block_with_threat_repeated_triggers_ban(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False,
        enable_ip_banning=True,
        auto_ban_threshold=2,
        auto_ban_duration=300,
    )
    mw = _make_middleware(config)
    check = IpSecurityCheck(mw)
    ban = AsyncMock()
    check.ip_ban_manager = ban

    with (
        patch(
            "guard_core.core.checks.implementations.ip_security.check_ip_access",
            new_callable=AsyncMock,
            return_value=IpAccessResult(False, "blocked"),
        ),
        patch("guard_core.core.checks.implementations.ip_security.log_activity"),
    ):
        _patch_detect_threat(monkeypatch)
        await check._check_global_ip_restrictions(_make_request("21.0.0.1"), "21.0.0.1")
        assert ban.ban_ip.call_count == 0
        await check._check_global_ip_restrictions(_make_request("21.0.0.1"), "21.0.0.1")

    ban.ban_ip.assert_called_once_with("21.0.0.1", 300, "penetration_attempt")


async def test_global_ip_block_no_threat_no_counter_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False, enable_ip_banning=True, auto_ban_threshold=1
    )
    mw = _make_middleware(config)
    check = IpSecurityCheck(mw)
    ban = AsyncMock()
    check.ip_ban_manager = ban

    with (
        patch(
            "guard_core.core.checks.implementations.ip_security.check_ip_access",
            new_callable=AsyncMock,
            return_value=IpAccessResult(False, "blocked"),
        ),
        patch("guard_core.core.checks.implementations.ip_security.log_activity"),
    ):
        _patch_detect_threat(monkeypatch, is_threat=False, trigger_info="not_enabled")
        result = await check._check_global_ip_restrictions(
            _make_request("22.0.0.1"), "22.0.0.1"
        )

    assert result is not None
    assert mw.suspicious_request_counts == {}
    ban.ban_ip.assert_not_called()


async def test_global_ip_block_passive_mode_no_escalation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=True, enable_ip_banning=True, auto_ban_threshold=1
    )
    mw = _make_middleware(config)
    check = IpSecurityCheck(mw)
    ban = AsyncMock()
    check.ip_ban_manager = ban

    detect_called: list[int] = []

    async def spy_detect(*_args: Any, **_kwargs: Any) -> DetectionResult:
        detect_called.append(1)
        return DetectionResult(
            is_threat=True, trigger_info="t", threat_categories=["xss"]
        )

    monkeypatch.setattr(
        "guard_core.core.checks.helpers.detect_penetration_patterns", spy_detect
    )

    with (
        patch(
            "guard_core.core.checks.implementations.ip_security.check_ip_access",
            new_callable=AsyncMock,
            return_value=IpAccessResult(False, "blocked"),
        ),
        patch("guard_core.core.checks.implementations.ip_security.log_activity"),
    ):
        result = await check._check_global_ip_restrictions(
            _make_request("23.0.0.1"), "23.0.0.1"
        )

    assert result is None
    assert mw.suspicious_request_counts == {}
    ban.ban_ip.assert_not_called()
    assert detect_called == []


async def test_route_ip_block_with_threat_increments_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False, enable_ip_banning=True, auto_ban_threshold=1000
    )
    mw = _make_middleware(config)
    check = IpSecurityCheck(mw)
    ban = AsyncMock()
    check.ip_ban_manager = ban
    from guard_core.decorators.base import RouteConfig

    request = _make_request("24.0.0.1")

    with (
        patch(
            "guard_core.core.checks.implementations.ip_security.check_route_ip_access",
            new_callable=AsyncMock,
            return_value=False,
        ),
        patch("guard_core.core.checks.implementations.ip_security.log_activity"),
    ):
        _patch_detect_threat(monkeypatch)
        result = await check._check_route_ip_restrictions(
            request, "24.0.0.1", RouteConfig()
        )

    assert result is not None
    assert mw.suspicious_request_counts["24.0.0.1"] == {"xss": 1}


async def test_route_ip_block_passive_mode_no_escalation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=True, enable_ip_banning=True, auto_ban_threshold=1
    )
    mw = _make_middleware(config)
    check = IpSecurityCheck(mw)
    ban = AsyncMock()
    check.ip_ban_manager = ban
    from guard_core.decorators.base import RouteConfig

    detect_called: list[int] = []

    async def spy_detect(*_args: Any, **_kwargs: Any) -> DetectionResult:
        detect_called.append(1)
        return DetectionResult(
            is_threat=True, trigger_info="t", threat_categories=["xss"]
        )

    monkeypatch.setattr(
        "guard_core.core.checks.helpers.detect_penetration_patterns", spy_detect
    )

    with (
        patch(
            "guard_core.core.checks.implementations.ip_security.check_route_ip_access",
            new_callable=AsyncMock,
            return_value=False,
        ),
        patch("guard_core.core.checks.implementations.ip_security.log_activity"),
    ):
        result = await check._check_route_ip_restrictions(
            _make_request("25.0.0.1"), "25.0.0.1", RouteConfig()
        )

    assert result is None
    assert mw.suspicious_request_counts == {}
    assert detect_called == []


async def test_user_agent_block_with_threat_increments_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False,
        enable_ip_banning=True,
        auto_ban_threshold=1000,
        blocked_user_agents=[r"badbot"],
    )
    mw = _make_middleware(config)
    check = UserAgentCheck(mw)
    ban = AsyncMock()
    check.ip_ban_manager = ban
    request = _make_request("26.0.0.1")

    _patch_detect_threat(monkeypatch)

    result = await check.check(request)

    assert result is not None
    assert mw.suspicious_request_counts["26.0.0.1"] == {"xss": 1}


async def test_user_agent_block_with_threat_repeated_triggers_ban(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False,
        enable_ip_banning=True,
        auto_ban_threshold=2,
        auto_ban_duration=300,
        blocked_user_agents=[r"badbot"],
    )
    mw = _make_middleware(config)
    check = UserAgentCheck(mw)
    ban = AsyncMock()
    check.ip_ban_manager = ban

    _patch_detect_threat(monkeypatch)

    await check.check(_make_request("27.0.0.1"))
    assert ban.ban_ip.call_count == 0
    await check.check(_make_request("27.0.0.1"))
    ban.ban_ip.assert_called_once_with("27.0.0.1", 300, "penetration_attempt")


async def test_user_agent_block_no_threat_no_counter_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False,
        enable_ip_banning=True,
        auto_ban_threshold=1,
        blocked_user_agents=[r"badbot"],
    )
    mw = _make_middleware(config)
    check = UserAgentCheck(mw)
    ban = AsyncMock()
    check.ip_ban_manager = ban

    _patch_detect_threat(monkeypatch, is_threat=False, trigger_info="not_enabled")

    result = await check.check(_make_request("28.0.0.1"))

    assert result is not None
    assert mw.suspicious_request_counts == {}
    ban.ban_ip.assert_not_called()


async def test_user_agent_block_passive_mode_no_escalation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=True,
        enable_ip_banning=True,
        auto_ban_threshold=1,
        blocked_user_agents=[r"badbot"],
    )
    mw = _make_middleware(config)
    check = UserAgentCheck(mw)
    ban = AsyncMock()
    check.ip_ban_manager = ban

    detect_called: list[int] = []

    async def spy_detect(*_args: Any, **_kwargs: Any) -> DetectionResult:
        detect_called.append(1)
        return DetectionResult(
            is_threat=True, trigger_info="t", threat_categories=["xss"]
        )

    monkeypatch.setattr(
        "guard_core.core.checks.helpers.detect_penetration_patterns", spy_detect
    )

    result = await check.check(_make_request("29.0.0.1"))

    assert result is None
    assert mw.suspicious_request_counts == {}
    assert detect_called == []


async def test_user_agent_block_no_client_ip_skips_escalation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False,
        enable_ip_banning=True,
        auto_ban_threshold=1,
        blocked_user_agents=[r"badbot"],
    )
    mw = _make_middleware(config)
    check = UserAgentCheck(mw)
    ban = AsyncMock()
    check.ip_ban_manager = ban

    detect_called: list[int] = []

    async def spy_detect(*_args: Any, **_kwargs: Any) -> DetectionResult:
        detect_called.append(1)
        return DetectionResult(
            is_threat=True, trigger_info="t", threat_categories=["xss"]
        )

    monkeypatch.setattr(
        "guard_core.core.checks.helpers.detect_penetration_patterns", spy_detect
    )

    result = await check.check(_make_request(None))

    assert result is not None
    assert mw.suspicious_request_counts == {}
    assert detect_called == []


async def test_no_double_count_blocked_probe_increments_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False,
        enable_ip_banning=True,
        auto_ban_threshold=1000,
        blocked_user_agents=[r"badbot"],
    )
    mw = _make_middleware(config)
    check = UserAgentCheck(mw)
    check.ip_ban_manager = AsyncMock()

    detect_calls: list[int] = []

    async def counting_detect(*_args: Any, **_kwargs: Any) -> DetectionResult:
        detect_calls.append(1)
        return DetectionResult(
            is_threat=True, trigger_info="t", threat_categories=["xss"]
        )

    monkeypatch.setattr(
        "guard_core.core.checks.helpers.detect_penetration_patterns", counting_detect
    )

    await check.check(_make_request("30.0.0.1"))

    assert len(detect_calls) == 1
    assert mw.suspicious_request_counts["30.0.0.1"] == {"xss": 1}


async def test_global_ip_block_still_returns_403_when_ban_ip_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False,
        enable_ip_banning=True,
        auto_ban_threshold=1,
        auto_ban_duration=7200,
    )
    mw = _make_middleware(config)
    check = IpSecurityCheck(mw)
    ban = AsyncMock()
    ban.ban_ip = AsyncMock(side_effect=ValueError("duration exceeds local cap"))
    check.ip_ban_manager = ban

    _patch_detect_threat(monkeypatch)

    with (
        patch(
            "guard_core.core.checks.implementations.ip_security.check_ip_access",
            new_callable=AsyncMock,
            return_value=IpAccessResult(False, "blocked"),
        ),
        patch("guard_core.core.checks.implementations.ip_security.log_activity"),
    ):
        result = await check._check_global_ip_restrictions(
            _make_request("50.0.0.1"), "50.0.0.1"
        )

    assert result is not None
    assert result.status_code == 403
    ban.ban_ip.assert_called_once_with("50.0.0.1", 7200, "penetration_attempt")
    mw.logger.exception.assert_called_once()
    assert mw.logger.exception.call_args.args[1] == "50.0.0.1"


async def test_user_agent_block_still_returns_403_when_ban_ip_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False,
        enable_ip_banning=True,
        auto_ban_threshold=1,
        auto_ban_duration=7200,
        blocked_user_agents=[r"badbot"],
    )
    mw = _make_middleware(config)
    check = UserAgentCheck(mw)
    ban = AsyncMock()
    ban.ban_ip = AsyncMock(side_effect=ValueError("duration exceeds local cap"))
    check.ip_ban_manager = ban

    _patch_detect_threat(monkeypatch)

    result = await check.check(_make_request("51.0.0.1"))

    assert result is not None
    assert result.status_code == 403
    ban.ban_ip.assert_called_once_with("51.0.0.1", 7200, "penetration_attempt")
    mw.logger.exception.assert_called_once()
    assert mw.logger.exception.call_args.args[1] == "51.0.0.1"
