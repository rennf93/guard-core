import ast
import json
import logging
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import guard_core
from guard_core.core.checks.implementations.ip_security import IpSecurityCheck
from guard_core.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest


def _make_middleware(config: SecurityConfig) -> MagicMock:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("guard_core.test.wire_redaction")
    middleware.event_bus = MagicMock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(
        return_value=MagicMock(status_code=403)
    )
    middleware.route_resolver = MagicMock()
    middleware.route_resolver.should_bypass_check = MagicMock(return_value=False)
    middleware.geo_ip_handler = None
    return middleware


async def test_blocked_request_log_redacts_authorization_and_custom_sensitive_header(
    caplog: pytest.LogCaptureFixture,
) -> None:
    client_ip = "203.0.113.50"
    config = SecurityConfig(
        blacklist=[client_ip],
        log_sensitive_headers={"x-internal-token"},
    )
    middleware = _make_middleware(config)
    check = IpSecurityCheck(middleware)
    pipeline = SecurityCheckPipeline([check])

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={
            "Authorization": "Bearer wire-secret",
            "X-Internal-Token": "wire-internal",
        },
        client_host=client_ip,
    )
    request.state.client_ip = client_ip
    request.state.route_config = None

    with patch.object(check, "ip_ban_manager") as mock_ban_manager:
        mock_ban_manager.is_ip_banned = AsyncMock(return_value=False)
        with caplog.at_level(logging.WARNING):
            result = await pipeline.execute(request)

    assert result is not None
    block_lines = [
        line for line in caplog.text.splitlines() if "IP not allowed" in line
    ]
    assert block_lines, "no block log line captured"
    block_line = block_lines[0]
    assert block_line.count("[REDACTED]") == 2
    assert "wire-secret" not in block_line
    assert "wire-internal" not in block_line


async def test_suspicious_activity_check_log_redacts_json_field_in_non_sensitive_header(
    caplog: pytest.LogCaptureFixture,
) -> None:
    client_ip = "203.0.113.70"
    config = SecurityConfig()
    middleware = _make_middleware(config)
    check = SuspiciousActivityCheck(middleware)
    pipeline = SecurityCheckPipeline([check])

    secret = "PIPE-JSON-SECRET"
    payload = json.dumps({"password": secret, "note": "<script>alert(1)</script>"})
    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Custom": payload},
        client_host=client_ip,
    )
    request.state.client_ip = client_ip
    request.state.route_config = None

    with caplog.at_level(logging.WARNING):
        result = await pipeline.execute(request)

    assert result is not None
    lines = [
        line
        for line in caplog.text.splitlines()
        if "Suspicious activity detected" in line
    ]
    assert lines, "no suspicious activity log line captured"
    assert '"password":"[REDACTED]"' in lines[0]
    assert secret not in caplog.text


def _log_activity_call_sites() -> list[tuple[Path, ast.Call]]:
    guard_core_root = Path(guard_core.__file__).resolve().parent
    sites: list[tuple[Path, ast.Call]] = []
    for path in guard_core_root.rglob("*.py"):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = (
                func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
            )
            if name == "log_activity":
                sites.append((path, node))
    return sites


def test_every_log_activity_call_site_passes_sensitive_headers() -> None:
    sites = _log_activity_call_sites()
    assert sites, "no log_activity call sites found; guard is vacuous"

    guard_core_root = Path(guard_core.__file__).resolve().parent
    sync_sites = [
        path for path, _ in sites if "sync" in path.relative_to(guard_core_root).parts
    ]
    non_sync_sites = [
        path
        for path, _ in sites
        if "sync" not in path.relative_to(guard_core_root).parts
    ]
    assert sync_sites, "no log_activity call sites found under guard_core/sync/"
    assert non_sync_sites, "no log_activity call sites found outside guard_core/sync/"

    missing = [
        f"{path}:{node.lineno}"
        for path, node in sites
        if not any(kw.arg == "sensitive_headers" for kw in node.keywords)
    ]
    assert not missing, f"log_activity call sites missing sensitive_headers=: {missing}"

    missing_params = [
        f"{path}:{node.lineno}"
        for path, node in sites
        if not any(kw.arg == "sensitive_params" for kw in node.keywords)
    ]
    assert not missing_params, (
        f"log_activity call sites missing sensitive_params=: {missing_params}"
    )

    missing_body_fields = [
        f"{path}:{node.lineno}"
        for path, node in sites
        if not any(kw.arg == "sensitive_body_fields" for kw in node.keywords)
    ]
    assert not missing_body_fields, (
        f"log_activity call sites missing sensitive_body_fields=: {missing_body_fields}"
    )
