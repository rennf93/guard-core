from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.checks.helpers import escalate_suspicious_if_threat
from guard_core.detection_result import DetectionResult
from guard_core.models import SecurityConfig, ThreatBanConfig


def _make_middleware(counts: dict[str, dict[str, int]] | None = None) -> Any:
    mw = MagicMock()
    mw.suspicious_request_counts = counts if counts is not None else {}
    mw.route_resolver = MagicMock()
    mw.route_resolver.should_bypass_check = lambda *_: False
    return mw


def _make_request(route_config: Any = None) -> Any:
    request = MagicMock()
    request.state = MagicMock()
    request.state.route_config = route_config
    return request


def _patch_detect(
    monkeypatch: pytest.MonkeyPatch,
    result: DetectionResult,
) -> None:
    async def fake_detect(*_args: Any, **_kwargs: Any) -> DetectionResult:
        return result

    monkeypatch.setattr(
        "guard_core.core.checks.helpers.detect_penetration_patterns", fake_detect
    )


def _patch_log(monkeypatch: pytest.MonkeyPatch) -> Any:
    log_mock = AsyncMock()
    monkeypatch.setattr("guard_core.core.checks.helpers.log_activity", log_mock)
    return log_mock


async def test_no_threat_no_counter_change_no_ban(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(enable_ip_banning=True)
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(
        monkeypatch, DetectionResult(is_threat=False, trigger_info="not_enabled")
    )
    _patch_log(monkeypatch)

    await escalate_suspicious_if_threat(
        mw, config, ban, _make_request(), "1.1.1.1", MagicMock(), "ip_security", set()
    )

    assert mw.suspicious_request_counts == {}
    ban.ban_ip.assert_not_called()


async def test_threat_increments_per_category(monkeypatch: pytest.MonkeyPatch) -> None:
    config = SecurityConfig(enable_ip_banning=False)
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(
        monkeypatch,
        DetectionResult(
            is_threat=True,
            trigger_info="xss hit",
            threat_categories=["xss", "sqli"],
        ),
    )
    _patch_log(monkeypatch)

    await escalate_suspicious_if_threat(
        mw, config, ban, _make_request(), "2.2.2.2", MagicMock(), "ip_security", set()
    )

    assert mw.suspicious_request_counts["2.2.2.2"] == {"xss": 1, "sqli": 1}
    ban.ban_ip.assert_not_called()


async def test_ip_banning_disabled_no_ban(monkeypatch: pytest.MonkeyPatch) -> None:
    config = SecurityConfig(enable_ip_banning=False, auto_ban_threshold=1)
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(
        monkeypatch,
        DetectionResult(is_threat=True, trigger_info="t", threat_categories=["xss"]),
    )
    _patch_log(monkeypatch)

    await escalate_suspicious_if_threat(
        mw, config, ban, _make_request(), "3.3.3.3", MagicMock(), "ip_security", set()
    )

    assert mw.suspicious_request_counts["3.3.3.3"] == {"xss": 1}
    ban.ban_ip.assert_not_called()


async def test_per_category_below_threshold_no_ban(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        enable_ip_banning=True,
        auto_ban_threshold=1000,
        threat_ban_config={"xss": ThreatBanConfig(threshold=5, duration=99)},
    )
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(
        monkeypatch,
        DetectionResult(is_threat=True, trigger_info="t", threat_categories=["xss"]),
    )
    _patch_log(monkeypatch)

    await escalate_suspicious_if_threat(
        mw, config, ban, _make_request(), "4.4.4.4", MagicMock(), "ip_security", set()
    )

    assert mw.suspicious_request_counts["4.4.4.4"] == {"xss": 1}
    ban.ban_ip.assert_not_called()


async def test_per_category_meets_threshold_bans_and_returns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        enable_ip_banning=True,
        auto_ban_threshold=1000,
        threat_ban_config={"xss": ThreatBanConfig(threshold=1, duration=86400)},
    )
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(
        monkeypatch,
        DetectionResult(is_threat=True, trigger_info="t", threat_categories=["xss"]),
    )
    log_mock = _patch_log(monkeypatch)

    await escalate_suspicious_if_threat(
        mw, config, ban, _make_request(), "5.5.5.5", MagicMock(), "ip_security", set()
    )

    ban.ban_ip.assert_called_once_with("5.5.5.5", 86400, "penetration_attempt:xss")
    log_mock.assert_called_once()
    assert log_mock.call_args.kwargs["check_name"] == "ip_security"


async def test_per_category_returns_after_first_banning_category(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        enable_ip_banning=True,
        auto_ban_threshold=1000,
        threat_ban_config={
            "sqli": ThreatBanConfig(threshold=1, duration=111),
            "xss": ThreatBanConfig(threshold=1, duration=222),
        },
    )
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(
        monkeypatch,
        DetectionResult(
            is_threat=True, trigger_info="t", threat_categories=["sqli", "xss"]
        ),
    )
    _patch_log(monkeypatch)

    await escalate_suspicious_if_threat(
        mw, config, ban, _make_request(), "6.6.6.6", MagicMock(), "ip_security", set()
    )

    ban.ban_ip.assert_called_once_with("6.6.6.6", 111, "penetration_attempt:sqli")


async def test_flat_threshold_met_no_per_category_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        enable_ip_banning=True, auto_ban_threshold=2, auto_ban_duration=300
    )
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(
        monkeypatch,
        DetectionResult(is_threat=True, trigger_info="t", threat_categories=["xss"]),
    )
    _patch_log(monkeypatch)

    await escalate_suspicious_if_threat(
        mw, config, ban, _make_request(), "7.7.7.7", MagicMock(), "ip_security", set()
    )
    assert ban.ban_ip.call_count == 0

    await escalate_suspicious_if_threat(
        mw, config, ban, _make_request(), "7.7.7.7", MagicMock(), "ip_security", set()
    )
    ban.ban_ip.assert_called_once_with("7.7.7.7", 300, "penetration_attempt")


async def test_disabled_by_decorator_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    config = SecurityConfig(enable_ip_banning=True, auto_ban_threshold=1)
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(
        monkeypatch,
        DetectionResult(is_threat=False, trigger_info="disabled_by_decorator"),
    )
    _patch_log(monkeypatch)

    await escalate_suspicious_if_threat(
        mw, config, ban, _make_request(), "8.8.8.8", MagicMock(), "ip_security", set()
    )

    assert mw.suspicious_request_counts == {}
    ban.ban_ip.assert_not_called()


async def test_empty_threat_categories_increments_uncategorized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(enable_ip_banning=True, auto_ban_threshold=1)
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(
        monkeypatch,
        DetectionResult(is_threat=True, trigger_info="t", threat_categories=[]),
    )
    _patch_log(monkeypatch)

    await escalate_suspicious_if_threat(
        mw, config, ban, _make_request(), "9.9.9.9", MagicMock(), "ip_security", set()
    )

    assert mw.suspicious_request_counts["9.9.9.9"] == {"uncategorized": 1}
    ban.ban_ip.assert_called_once_with(
        "9.9.9.9", config.auto_ban_duration, "penetration_attempt"
    )


async def test_falsy_client_ip_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    config = SecurityConfig(enable_ip_banning=True, auto_ban_threshold=1)
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(
        monkeypatch,
        DetectionResult(is_threat=True, trigger_info="t", threat_categories=["xss"]),
    )
    _patch_log(monkeypatch)

    await escalate_suspicious_if_threat(
        mw, config, ban, _make_request(), "", MagicMock(), "ip_security", set()
    )

    assert mw.suspicious_request_counts == {}
    ban.ban_ip.assert_not_called()


async def test_neither_ban_fires_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        enable_ip_banning=True,
        auto_ban_threshold=1000,
        threat_ban_config={"xss": ThreatBanConfig(threshold=100, duration=99)},
    )
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(
        monkeypatch,
        DetectionResult(is_threat=True, trigger_info="t", threat_categories=["xss"]),
    )
    _patch_log(monkeypatch)

    await escalate_suspicious_if_threat(
        mw, config, ban, _make_request(), "10.0.0.1", MagicMock(), "ip_security", set()
    )

    assert mw.suspicious_request_counts["10.0.0.1"] == {"xss": 1}
    ban.ban_ip.assert_not_called()


async def test_per_category_entry_missing_falls_to_flat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        enable_ip_banning=True, auto_ban_threshold=1, auto_ban_duration=60
    )
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(
        monkeypatch,
        DetectionResult(is_threat=True, trigger_info="t", threat_categories=["sqli"]),
    )
    _patch_log(monkeypatch)

    await escalate_suspicious_if_threat(
        mw, config, ban, _make_request(), "11.0.0.1", MagicMock(), "ip_security", set()
    )

    ban.ban_ip.assert_called_once_with("11.0.0.1", 60, "penetration_attempt")


async def test_muted_check_logs_suppresses_log(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        enable_ip_banning=True, auto_ban_threshold=1, auto_ban_duration=60
    )
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(
        monkeypatch,
        DetectionResult(is_threat=True, trigger_info="t", threat_categories=["xss"]),
    )
    log_mock = _patch_log(monkeypatch)

    await escalate_suspicious_if_threat(
        mw,
        config,
        ban,
        _make_request(),
        "12.0.0.1",
        MagicMock(),
        "ip_security",
        {"ip_security"},
    )

    ban.ban_ip.assert_called_once()
    log_mock.assert_called_once()
    assert log_mock.call_args.kwargs["muted_check_logs"] == {"ip_security"}
