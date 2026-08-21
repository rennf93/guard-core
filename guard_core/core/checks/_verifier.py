import inspect
from typing import Any


async def resolve_verifier_result(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value
