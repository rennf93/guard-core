import json

import pytest

from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import SecurityConfig
from guard_core.utils import _scan_json_value, detect_penetration_attempt
from tests.conftest import MockGuardRequest

_CONFIG = SecurityConfig()


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


def _json_body_request(payload: dict) -> MockGuardRequest:
    body = json.dumps(payload).encode()
    headers = {"content-length": str(len(body)), "content-type": "application/json"}
    return MockGuardRequest(body_content=body, headers=headers)


@pytest.mark.parametrize(
    "payload",
    [
        {"username": {"$ne": None}},
        {"$ne": 1},
        {"$gt": "x"},
        {"a": {"$where": "this.x==1"}},
        {"a": {"$regex": ".*"}},
    ],
)
async def test_json_operator_key_detected_as_nosql(payload: dict) -> None:
    request = _json_body_request(payload)
    result = await detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.threat_categories == ["nosql"]


@pytest.mark.parametrize(
    "payload",
    [
        {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "$ref": "#/definitions/x",
            "$id": "https://example.com/schema.json",
            "$defs": {},
            "$anchor": "y",
            "$comment": "z",
        },
        {"price": 100, "name": "x"},
        {"a": {"b": {"c": {"d": 1}}}},
    ],
)
async def test_benign_json_not_detected(payload: dict) -> None:
    request = _json_body_request(payload)
    result = await detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is False


@pytest.mark.parametrize(
    "payload",
    [
        {"price": {"$gt": 100}},
        {"age": {"$ne": None}},
    ],
)
async def test_operator_query_json_twin_fires_nosql(payload: dict) -> None:
    request = _json_body_request(payload)
    result = await detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.threat_categories == ["nosql"]


async def test_excluded_body_field_suppresses_operator_key() -> None:
    detected, trigger, threats = await _scan_json_value(
        {"username": {"$ne": 1}},
        "",
        {"$ne"},
        None,
        "127.0.0.1",
        "corr-1",
        "WARNING",
    )
    assert detected is False
    assert trigger == ""
    assert threats == []
