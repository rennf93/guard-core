"""Async function-wrapping decorator for protecting LLM calls.

Unlike the route decorators in ``guard_core.decorators``, this is a plain
function wrapper: decorate an ``async`` callable that takes user text and
returns an LLM response, and every invocation will run pre-call input
scanning (via ``PromptGuard.protect_input``) and post-call canary
verification (via ``PromptGuard.verify_output``) around the wrapped
function. The wrapped function is substituted with the sanitised input
transparently.

This decorator is **async-only** by design — LLM calls in practice are
overwhelmingly async, and keeping the sync/async dispatch out of the
critical path makes coverage, warnings, and reasoning all simpler. If
you have a sync LLM call, wrap it yourself via ``PromptGuard`` methods
directly.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from guard_core.prompt_injection.prompt_guard import (
    PromptGuard,
    PromptInjectionAttempt,
)

_default_guard: PromptGuard | None = None


def _get_default_guard() -> PromptGuard:
    global _default_guard
    if _default_guard is None:
        _default_guard = PromptGuard()
    return _default_guard


def _resolve(
    key: int | str | None,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> Any:
    if key is None:
        return None
    if isinstance(key, int):
        if key < len(args):
            return args[key]
        return None
    return kwargs.get(key)


def _substitute(
    key: int | str,
    value: Any,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> tuple[tuple[Any, ...], dict[str, Any]]:
    if isinstance(key, int):
        new_args = list(args)
        new_args[key] = value
        return tuple(new_args), kwargs
    new_kwargs = dict(kwargs)
    new_kwargs[key] = value
    return args, new_kwargs


def _scan_input(
    guard: PromptGuard,
    raw_input: Any,
    session_id: Any,
) -> str:
    if not isinstance(raw_input, str):
        kind = type(raw_input).__name__
        raise TypeError(
            f"protect_prompt: extracted input is not a string ({kind}); "
            "provide a custom extractor for non-string shapes."
        )
    session = session_id if isinstance(session_id, str) else None
    return guard.protect_input(raw_input, session)


def _verify_output(
    guard: PromptGuard,
    output: Any,
    extract_output: Callable[[Any], Any] | None,
) -> None:
    if not guard.enable_canary:
        return
    if extract_output is not None:
        text = extract_output(output)
    elif isinstance(output, str):
        text = output
    else:
        return
    if not isinstance(text, str):
        return
    if not guard.verify_output(text):
        raise PromptInjectionAttempt(
            "Canary token leaked in LLM response",
            detection_layer="canary",
        )


def protect_prompt(
    guard: PromptGuard | None = None,
    input_key: int | str = 0,
    session_id_key: int | str | None = None,
    extract_output: Callable[[Any], Any] | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Wrap an async callable so its input is scanned and output canary-checked.

    Args:
        guard: ``PromptGuard`` instance to use. A module-level default is
            created lazily when omitted; share one explicitly across
            decorators if you want common session/canary state.
        input_key: Position (int) or keyword name (str) of the user-input
            argument in the decorated callable's signature. Default ``0``
            (first positional argument).
        session_id_key: Optional position or keyword of a session
            identifier argument, forwarded to ``PromptGuard.protect_input``
            for per-session canary / context.
        extract_output: Optional callable that pulls a string out of the
            wrapped function's return value. Use this when the callable
            returns a provider-specific object (e.g. OpenAI response
            objects). When omitted and the return is non-string, output
            verification is skipped.

    Raises:
        PromptInjectionAttempt: Via ``PromptGuard.protect_input`` when the
            input is flagged above the detection threshold, or when the
            canary token leaks in the output.
        TypeError: When the extracted input is not a string.
    """
    resolved_guard = guard or _get_default_guard()

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            raw_input = _resolve(input_key, args, kwargs)
            session = _resolve(session_id_key, args, kwargs)
            sanitized = _scan_input(resolved_guard, raw_input, session)
            new_args, new_kwargs = _substitute(input_key, sanitized, args, kwargs)
            result = await func(*new_args, **new_kwargs)
            _verify_output(resolved_guard, result, extract_output)
            return result

        return wrapper

    return decorator


def reset_default_guard() -> None:
    """Drop the module-level default guard.

    Useful in tests that need a fresh canary manager or detector state
    between invocations. Production code should prefer passing an
    explicit ``guard`` to ``protect_prompt``.
    """
    global _default_guard
    _default_guard = None
