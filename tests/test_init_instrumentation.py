import builtins
import logging
from collections.abc import Mapping, Sequence
from types import ModuleType
from typing import Any

import pytest

import guard_core
from guard_core import _pydantic_plugin_mute


def test_mute_pydantic_instrumentation_is_noop_without_agent_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the guard-agent extra is not installed, muting the telemetry models'
    pydantic-plugin instrumentation must be a clean no-op, not an ImportError."""
    monkeypatch.setattr(_pydantic_plugin_mute, "_applied", False)

    real_import = builtins.__import__

    def fake_import(
        name: str,
        globals: Mapping[str, object] | None = None,
        locals: Mapping[str, object] | None = None,
        fromlist: Sequence[str] = (),
        level: int = 0,
    ) -> ModuleType:
        if name == "guard_agent.models":
            raise ImportError("guard-agent extra not installed")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    guard_core._mute_pydantic_plugin_instrumentation()


def test_mute_pydantic_instrumentation_survives_rebuild_failure(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A guard-agent model that cannot be force-rebuilt must degrade to
    instrumentation-left-on instead of crashing."""
    from guard_agent.models import SecurityEvent

    monkeypatch.setattr(_pydantic_plugin_mute, "_applied", False)

    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("rebuild failed")

    monkeypatch.setattr(SecurityEvent, "model_rebuild", boom)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        guard_core._mute_pydantic_plugin_instrumentation()

    assert "Could not opt guard-agent telemetry models" in caplog.text


def test_mute_pydantic_instrumentation_is_idempotent_after_first_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A second call in the same process must not re-run `model_rebuild`;
    only the first call in the process does any work."""
    from guard_agent.models import EventBatch, SecurityEvent, SecurityMetric

    monkeypatch.setattr(_pydantic_plugin_mute, "_applied", False)

    rebuild_calls: list[str] = []

    def _count_rebuild(model: type[Any]) -> None:
        original = model.model_rebuild

        def wrapper(*args: object, **kwargs: object) -> Any:
            rebuild_calls.append(model.__name__)
            return original(*args, **kwargs)

        monkeypatch.setattr(model, "model_rebuild", wrapper)

    for model in (SecurityEvent, SecurityMetric, EventBatch):
        _count_rebuild(model)

    guard_core._mute_pydantic_plugin_instrumentation()
    assert len(rebuild_calls) == 3

    guard_core._mute_pydantic_plugin_instrumentation()
    assert len(rebuild_calls) == 3
