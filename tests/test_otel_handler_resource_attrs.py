import importlib
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SecurityConfig


def _fresh_otel_handler_module():
    module_name = "guard_core.core.events.otel_handler"
    if module_name in sys.modules:
        return importlib.reload(sys.modules[module_name])
    return importlib.import_module(module_name)


@pytest.fixture(autouse=True)
def _reload_otel_handler_between_tests():
    _fresh_otel_handler_module()
    yield
    _fresh_otel_handler_module()


def test_otel_resource_attributes_default_empty() -> None:
    assert SecurityConfig().otel_resource_attributes == {}


def test_otel_resource_attributes_accepts_map() -> None:
    config = SecurityConfig(
        otel_resource_attributes={
            "deployment.environment": "prod",
            "service.version": "1.0.3",
        }
    )
    assert config.otel_resource_attributes["deployment.environment"] == "prod"
    assert config.otel_resource_attributes["service.version"] == "1.0.3"


async def test_otel_handler_applies_resource_attributes() -> None:
    module = _fresh_otel_handler_module()
    fake_resource = MagicMock()
    fake_resource_cls = MagicMock()
    fake_resource_cls.create = MagicMock(return_value=fake_resource)

    with (
        patch.object(module, "_otel_available", True),
        patch.object(module, "Resource", fake_resource_cls),
        patch.object(module, "TracerProvider"),
        patch.object(module, "BatchSpanProcessor"),
        patch.object(module, "OTLPSpanExporter"),
        patch.object(module, "OTLPMetricExporter"),
        patch.object(module, "PeriodicExportingMetricReader"),
        patch.object(module, "MeterProvider"),
        patch.object(module, "trace"),
        patch.object(module, "metrics"),
    ):
        config = SimpleNamespace(
            otel_service_name="guard-core",
            otel_exporter_endpoint="http://localhost:4318",
            otel_resource_attributes={
                "deployment.environment": "prod",
                "service.version": "1.0.3",
            },
        )
        handler = module.OtelHandler(config)
        await handler.start()

    fake_resource_cls.create.assert_called_once()
    attrs = fake_resource_cls.create.call_args.args[0]
    assert attrs["service.name"] == "guard-core"
    assert attrs["deployment.environment"] == "prod"
    assert attrs["service.version"] == "1.0.3"


async def test_otel_handler_works_without_resource_attrs_field() -> None:
    module = _fresh_otel_handler_module()
    fake_resource = MagicMock()
    fake_resource_cls = MagicMock()
    fake_resource_cls.create = MagicMock(return_value=fake_resource)

    with (
        patch.object(module, "_otel_available", True),
        patch.object(module, "Resource", fake_resource_cls),
        patch.object(module, "TracerProvider"),
        patch.object(module, "BatchSpanProcessor"),
        patch.object(module, "OTLPSpanExporter"),
        patch.object(module, "OTLPMetricExporter"),
        patch.object(module, "PeriodicExportingMetricReader"),
        patch.object(module, "MeterProvider"),
        patch.object(module, "trace"),
        patch.object(module, "metrics"),
    ):
        config = SimpleNamespace(
            otel_service_name="guard-core",
            otel_exporter_endpoint=None,
        )
        handler = module.OtelHandler(config)
        await handler.start()

    attrs = fake_resource_cls.create.call_args.args[0]
    assert attrs == {"service.name": "guard-core"}
