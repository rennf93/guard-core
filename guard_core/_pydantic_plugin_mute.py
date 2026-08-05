import logging
from typing import Any, Literal, cast

_applied = False

TelemetryModelName = Literal["SecurityEvent", "SecurityMetric", "EventBatch"]


def _mute_pydantic_plugin_instrumentation() -> None:
    """Opt guard-agent's hot-path telemetry models out of pydantic plugin
    instrumentation (e.g. logfire.instrument_pydantic()).

    SecurityEvent/SecurityMetric are validated per request and EventBatch
    re-validates every buffered event on each flush, so an instrumented host
    app would otherwise emit a span per security event — hundreds of
    thousands a day under real traffic. plugin_settings is only read while
    building a model's validator, hence the forced rebuild.

    Idempotent: every guard-core path that can end up constructing one of
    these models calls this on its way there, so it may run once per
    SecurityConfig construction in a test suite; only the first call in the
    process does any work.
    """
    global _applied
    if _applied:
        return
    _applied = True

    try:
        from guard_agent.models import EventBatch, SecurityEvent, SecurityMetric
    except ImportError:
        return

    try:
        for model in (SecurityEvent, SecurityMetric, EventBatch):
            plugin_settings = cast(
                "dict[str, Any]",
                model.model_config.setdefault("plugin_settings", {}),
            )
            plugin_settings["logfire"] = {"record": "off"}
            model.model_rebuild(force=True)
    except Exception:
        logging.getLogger("guard_core").warning(
            "Could not opt guard-agent telemetry models out of pydantic "
            "plugin instrumentation",
            exc_info=True,
        )


def get_telemetry_model(name: TelemetryModelName) -> type[Any]:
    """The only sanctioned way for guard-core to obtain a guard-agent
    telemetry model class. Always mutes pydantic plugin instrumentation
    first, so no caller can construct SecurityEvent/SecurityMetric/EventBatch
    ahead of the mute; `tests/test_telemetry_model_access.py` scans the
    source tree and fails if any other module imports these models directly.
    """
    _mute_pydantic_plugin_instrumentation()
    import guard_agent

    return cast("type[Any]", getattr(guard_agent, name))
