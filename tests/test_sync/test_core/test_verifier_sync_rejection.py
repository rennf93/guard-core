import inspect

import pytest

from guard_core.sync.core.checks._verifier import resolve_verifier_result


def test_sync_resolve_returns_plain_value() -> None:
    assert resolve_verifier_result("principal") == "principal"


def test_sync_resolve_rejects_coroutine() -> None:
    async def verifier() -> str:
        return "principal"

    coro = verifier()
    assert inspect.isawaitable(coro)
    with pytest.raises(TypeError, match="sync"):
        resolve_verifier_result(coro)
    coro.close()
