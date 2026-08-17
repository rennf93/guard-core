import inspect

from guard_core.core.checks._verifier import resolve_verifier_result


async def test_resolve_verifier_result_returns_plain_value() -> None:
    assert await resolve_verifier_result("principal") == "principal"


async def test_resolve_verifier_result_awaits_coroutine() -> None:
    async def verifier() -> str:
        return "principal"

    coro = verifier()
    assert inspect.isawaitable(coro)
    assert await resolve_verifier_result(coro) == "principal"
