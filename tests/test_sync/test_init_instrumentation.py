import builtins
import logging
from collections.abc import Mapping, Sequence
from types import ModuleType

import pytest

import guard_core


def test_mute_pydantic_instrumentation_is_noop_without_agent_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the guard-agent extra is not installed, muting the telemetry models'
    pydantic-plugin instrumentation must be a clean no-op, not an ImportError."""
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
    instrumentation-left-on instead of crashing `import guard_core`."""
    from guard_agent.models import SecurityEvent

    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("rebuild failed")

    monkeypatch.setattr(SecurityEvent, "model_rebuild", boom)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        guard_core._mute_pydantic_plugin_instrumentation()

    assert "Could not opt guard-agent telemetry models" in caplog.text
