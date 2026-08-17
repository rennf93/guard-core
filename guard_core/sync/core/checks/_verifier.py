import inspect
from typing import Any


def resolve_verifier_result(value: Any) -> Any:
    if inspect.isawaitable(value):
        raise TypeError(
            "async verifier not supported in sync (WSGI) deployments; "
            "supply a sync verifier"
        )
    return value
