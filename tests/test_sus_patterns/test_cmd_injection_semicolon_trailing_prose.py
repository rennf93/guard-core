import pytest

from guard_core.handlers.suspatterns_handler import SusPatternsManager
from guard_core.models import SecurityConfig


def _manager() -> SusPatternsManager:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    manager = SusPatternsManager(SecurityConfig())
    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config
    return manager


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        "First run setup; /bin/sh -c 'ls' to verify.",
        "ticket note: reproduced by running commands; /bin/sh -c whoami showed root",
        "changelog: fixed default login; /bin/sh -x debug.sh now traces correctly",
    ],
)
async def test_shell_invocation_followed_by_trailing_prose_stays_benign(
    payload: str,
) -> None:
    manager = _manager()
    result = await manager.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False


@pytest.mark.asyncio
async def test_shell_invocation_with_nothing_trailing_is_still_detected() -> None:
    manager = _manager()
    payload = "/bin/sh -c 'npm start'"
    result = await manager.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )
