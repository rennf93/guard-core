import json
import logging
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock
from urllib.parse import quote, quote_plus, urlencode

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync._utils.detection_scan import _json_depth_cap_value
from guard_core.sync.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.core.events.otel_handler import OtelHandler
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import detect_penetration_attempt, log_activity
from tests.test_sync.conftest import SyncMockGuardRequest

try:
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    _otel_sdk_available = True
except ImportError:
    TracerProvider = None
    SimpleSpanProcessor = None
    InMemorySpanExporter = None
    _otel_sdk_available = False

_XSS = "<script>alert(1)</script>"
_SQLI = "' OR 1=1--"
_CONTENT_TYPE_MULTIPART = "multipart/form-data; boundary=B0"
_CUSTOM_SENSITIVE_HEADER = "x-custom-secret-header"
_CUSTOM_SENSITIVE_PARAM = "custom-secret-param"
_CUSTOM_SENSITIVE_BODY_FIELD = "custom_secret_field"
_PIPELINE_CLIENT_IP = "203.0.113.77"

_ON_BLOCK_CALLS: list[dict[str, Any]] = []


def _record_on_block(request: SyncGuardRequest, payload: dict[str, Any]) -> None:
    _ON_BLOCK_CALLS.append(payload)


def _build_config() -> SecurityConfig:
    return SecurityConfig(
        log_sensitive_headers={_CUSTOM_SENSITIVE_HEADER},
        log_sensitive_params={_CUSTOM_SENSITIVE_PARAM},
        log_sensitive_body_fields={_CUSTOM_SENSITIVE_BODY_FIELD},
        enable_ip_banning=False,
        passive_mode=False,
        on_block=_record_on_block,
    )


def _build_otel_handler(config: SecurityConfig) -> Any:
    if not _otel_sdk_available or InMemorySpanExporter is None:
        return None
    handler = OtelHandler(config)
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(_SPAN_EXPORTER))
    handler._tracer = provider.get_tracer("guard_core.otel")
    return handler


class _RecordingAgentHandler:
    def __init__(self, forward_to: Any | None = None) -> None:
        self.events: list[Any] = []
        self._forward_to = forward_to

    def send_event(self, event: Any) -> None:
        self.events.append(event)
        if self._forward_to is not None:
            self._forward_to.send_event(event)


def _build_middleware(config: SecurityConfig) -> MagicMock:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("guard_core.test.sensitive_invariant")
    middleware.event_bus = MagicMock()
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(
        return_value=MagicMock(status_code=400)
    )
    middleware.route_resolver = MagicMock()
    middleware.route_resolver.should_bypass_check = MagicMock(return_value=False)
    middleware.geo_ip_handler = None
    middleware.suspicious_request_counts = {}
    return middleware


_SPAN_EXPORTER: Any = InMemorySpanExporter() if _otel_sdk_available else None
_CONFIG = _build_config()
_OTEL_HANDLER = _build_otel_handler(_CONFIG)
_AGENT_RECORDER = _RecordingAgentHandler(forward_to=_OTEL_HANDLER)
_MIDDLEWARE = _build_middleware(_CONFIG)
_PIPELINE = SecurityCheckPipeline([SuspiciousActivityCheck(_MIDDLEWARE)])


class _UserinfoPasswordRequest(SyncMockGuardRequest):
    def __init__(self, *, password: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._userinfo_password = password

    @property
    def url_full(self) -> str:
        return f"{self.url_scheme}://user:{self._userinfo_password}@test{self.url_path}"


def _header_request(name: str, value: str) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(headers={name: value})


def _query_request(name: str, value: str) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(query_params={name: value})


def _path_request(path: str) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(path=path)


def _userinfo_request(password: str) -> SyncMockGuardRequest:
    return _UserinfoPasswordRequest(password=password, query_params={"trigger": _XSS})


def _json_body_request(body: bytes) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers={
            "content-type": "application/json",
            "content-length": str(len(body)),
        },
    )


def _form_body_request(fields: dict[str, str]) -> SyncMockGuardRequest:
    body = urlencode(fields).encode()
    return SyncMockGuardRequest(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "content-length": str(len(body)),
        },
    )


def _text_field_body(name: str, value: str) -> bytes:
    return (
        f'--B0\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'
        f"{value}\r\n--B0--\r\n"
    ).encode()


def _multipart_body_request(name: str, value: str) -> SyncMockGuardRequest:
    body = _text_field_body(name, value)
    return SyncMockGuardRequest(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers={
            "content-type": _CONTENT_TYPE_MULTIPART,
            "content-length": str(len(body)),
        },
    )


def _nested_wrapper_body(depth: int, wrapper_key: str, leaf: dict[str, str]) -> bytes:
    leaf_json = json.dumps(leaf)
    prefix = f'{{"{wrapper_key}":' * depth
    suffix = "}" * depth
    return (prefix + leaf_json + suffix).encode()


def _plain_pair(secret: str) -> str:
    return f"token={secret} {_XSS}"


def _pct_encode_pair(secret: str, rounds: int) -> str:
    value = f"{secret} {_XSS}"
    for _ in range(rounds):
        value = quote(value, safe="")
    return f"token={value}"


def _plus_for_space_pair(secret: str) -> str:
    return f"token={quote_plus(f'{secret} {_XSS}')}"


def _pct_equals_pair(secret: str) -> str:
    value = quote(f"{secret} {_XSS}", safe="")
    return f"token%3D{value}"


def _pct_amp_smuggle_pair(secret: str) -> str:
    raw_pair = f"token={secret} {_XSS}&y=2"
    return quote(raw_pair, safe="")


def _semicolon_pair(secret: str) -> str:
    return f"x=1;token={secret} {_XSS}"


def _uppercase_name_pair(secret: str) -> str:
    return f"TOKEN={secret} {_XSS}"


def _pct_encoded_name_pair(secret: str) -> str:
    encoded_name = "".join(f"%{ord(c):02X}" for c in "token")
    return f"{encoded_name}={secret} {_XSS}"


def _encoded_query_path_request(query_string: str) -> SyncMockGuardRequest:
    return _path_request(f"/resource?{query_string}")


@dataclass(frozen=True)
class Case:
    id: str
    request_factory: Callable[[str], SyncMockGuardRequest]


_CASES: list[Case] = [
    Case(
        "header_default_sensitive_name_direct_value",
        lambda secret: _header_request("Authorization", f"{secret} {_XSS}"),
    ),
    Case(
        "header_custom_sensitive_name_direct_value",
        lambda secret: _header_request(_CUSTOM_SENSITIVE_HEADER, f"{secret} {_XSS}"),
    ),
    Case(
        "header_non_sensitive_name_json_secret_under_sensitive_key",
        lambda secret: _header_request(
            "X-Info", json.dumps({"password": f"{secret} {_XSS}"})
        ),
    ),
    Case(
        "query_param_default_sensitive_name_direct_value",
        lambda secret: _query_request("token", f"{secret} {_SQLI}"),
    ),
    Case(
        "query_param_custom_sensitive_name_direct_value",
        lambda secret: _query_request(_CUSTOM_SENSITIVE_PARAM, f"{secret} {_SQLI}"),
    ),
    Case(
        "query_param_non_sensitive_name_json_secret_under_sensitive_key",
        lambda secret: _query_request(
            "data", json.dumps({"password": f"{secret} {_SQLI}"})
        ),
    ),
    Case(
        "path_segment_whole_path_is_json_secret_under_sensitive_key",
        lambda secret: _path_request(
            "/" + json.dumps({"password": f"{secret} {_XSS}"})
        ),
    ),
    Case(
        "path_segment_matrix_param_token",
        lambda secret: _path_request(f"/resource;token={secret} {_XSS}"),
    ),
    Case(
        "fragment_token_equals_value",
        lambda secret: _path_request(f"/route#token={secret} {_XSS}"),
    ),
    Case(
        "fragment_hash_route_question_token",
        lambda secret: _path_request(f"/route#/nested?token={secret} {_XSS}"),
    ),
    Case(
        "fragment_hash_a_equals_1_question_token",
        lambda secret: _path_request(f"/route#a=1?token={secret} {_XSS}"),
    ),
    Case(
        "userinfo_password_redacted_with_companion_trigger",
        lambda secret: _userinfo_request(secret),
    ),
    Case(
        "json_body_top_level_sensitive_key",
        lambda secret: _json_body_request(
            json.dumps({"password": f"{secret} {_SQLI}"}).encode()
        ),
    ),
    Case(
        "json_body_nested_three_levels_sensitive_key",
        lambda secret: _json_body_request(
            json.dumps({"a": {"b": {"password": f"{secret} {_SQLI}"}}}).encode()
        ),
    ),
    Case(
        "json_body_array_of_objects_sensitive_key",
        lambda secret: _json_body_request(
            json.dumps([{"note": "benign"}, {"password": f"{secret} {_SQLI}"}]).encode()
        ),
    ),
    Case(
        "json_body_sensitive_key_wraps_object_value",
        lambda secret: _json_body_request(
            json.dumps({"password": {"inner": f"{secret} {_SQLI}"}}).encode()
        ),
    ),
    Case(
        "json_body_sensitive_leaf_deeper_than_max_json_depth_under_non_sensitive_wrapper",
        lambda secret: _json_body_request(
            _nested_wrapper_body(
                _json_depth_cap_value(), "wrapper", {"password": f"{secret} {_SQLI}"}
            )
        ),
    ),
    Case(
        "form_body_default_sensitive_field_name",
        lambda secret: _form_body_request({"password": f"{secret} {_SQLI}"}),
    ),
    Case(
        "form_body_custom_sensitive_field_name",
        lambda secret: _form_body_request(
            {_CUSTOM_SENSITIVE_BODY_FIELD: f"{secret} {_SQLI}"}
        ),
    ),
    Case(
        "multipart_text_part_sensitive_field_name",
        lambda secret: _multipart_body_request("password", f"{secret} {_SQLI}"),
    ),
    Case(
        "url_encoding_plain",
        lambda secret: _encoded_query_path_request(_plain_pair(secret)),
    ),
    Case(
        "url_encoding_percent_encoded_once",
        lambda secret: _encoded_query_path_request(_pct_encode_pair(secret, 1)),
    ),
    Case(
        "url_encoding_percent_encoded_twice",
        lambda secret: _encoded_query_path_request(_pct_encode_pair(secret, 2)),
    ),
    Case(
        "url_encoding_percent_encoded_three_times",
        lambda secret: _encoded_query_path_request(_pct_encode_pair(secret, 3)),
    ),
    Case(
        "url_encoding_plus_for_space",
        lambda secret: _encoded_query_path_request(_plus_for_space_pair(secret)),
    ),
    Case(
        "url_encoding_percent_encoded_equals_separator",
        lambda secret: _encoded_query_path_request(_pct_equals_pair(secret)),
    ),
    Case(
        "url_encoding_percent_encoded_ampersand_smuggles_second_pair",
        lambda secret: _encoded_query_path_request(_pct_amp_smuggle_pair(secret)),
    ),
    Case(
        "url_encoding_semicolon_pair_separator",
        lambda secret: _encoded_query_path_request(_semicolon_pair(secret)),
    ),
    Case(
        "url_encoding_uppercase_param_name",
        lambda secret: _encoded_query_path_request(_uppercase_name_pair(secret)),
    ),
    Case(
        "url_encoding_percent_encoded_letters_in_param_name",
        lambda secret: _encoded_query_path_request(_pct_encoded_name_pair(secret)),
    ),
    Case(
        "size_query_param_value_over_100_chars_never_partially_leaks",
        lambda secret: _query_request("token", f"{secret}{'X' * 150} {_SQLI}"),
    ),
    Case(
        "size_json_body_300_level_nested_wrapper_must_not_raise",
        lambda secret: _json_body_request(
            _nested_wrapper_body(300, "wrapper", {"password": f"{secret} {_SQLI}"})
        ),
    ),
]


def _event_to_dict(event: Any) -> dict[str, Any]:
    if hasattr(event, "model_dump"):
        dumped: dict[str, Any] = event.model_dump(mode="json")
        return dumped
    return dict(vars(event))


def _events_dump(events: list[Any]) -> str:
    return json.dumps([_event_to_dict(event) for event in events], default=str)


def _on_block_dump(calls: list[dict[str, Any]]) -> str:
    return json.dumps(calls, default=str)


def _spans_dump(exporter: Any) -> str:
    spans = exporter.get_finished_spans()
    attrs = [dict(span.attributes or {}) for span in spans]
    return json.dumps(attrs, default=str)


@pytest.fixture(autouse=True)
def _reset_case_state() -> Iterator[None]:
    _ON_BLOCK_CALLS.clear()
    _AGENT_RECORDER.events.clear()
    _MIDDLEWARE.suspicious_request_counts.clear()
    if _otel_sdk_available and _SPAN_EXPORTER is not None:
        _SPAN_EXPORTER.clear()
    sus_patterns_handler.agent_handler = _AGENT_RECORDER
    try:
        yield
    finally:
        sus_patterns_handler.agent_handler = None


def test_case_matrix_has_unique_ids_and_covers_the_full_surface_list() -> None:
    ids = [case.id for case in _CASES]
    assert len(ids) == len(set(ids))
    assert len(_CASES) >= 30


@pytest.mark.parametrize("case", _CASES, ids=lambda case: case.id)
def test_sensitive_value_under_a_sensitive_name_never_reaches_guard_core_output(
    case: Case, caplog: pytest.LogCaptureFixture
) -> None:
    secret = f"SECRET-{case.id}"
    logger = logging.getLogger("guard_core.test.sensitive_invariant.direct")

    with caplog.at_level(logging.DEBUG):
        request = case.request_factory(secret)
        detection_result = detect_penetration_attempt(request, _CONFIG)

        log_activity(
            request,
            logger,
            log_type="request",
            level="INFO",
            sensitive_headers=_CONFIG.log_sensitive_headers,
            sensitive_params=_CONFIG.log_sensitive_params,
            sensitive_body_fields=_CONFIG.log_sensitive_body_fields,
        )
        log_activity(
            request,
            logger,
            log_type="suspicious",
            passive_mode=False,
            reason=f"Suspicious activity detected: {detection_result.trigger_info}",
            trigger_info=detection_result.trigger_info,
            level="WARNING",
            on_block=_record_on_block,
            sensitive_headers=_CONFIG.log_sensitive_headers,
            sensitive_params=_CONFIG.log_sensitive_params,
            sensitive_body_fields=_CONFIG.log_sensitive_body_fields,
        )
        log_activity(
            request,
            logger,
            log_type="suspicious",
            passive_mode=True,
            trigger_info=detection_result.trigger_info,
            level="WARNING",
            on_block=_record_on_block,
            sensitive_headers=_CONFIG.log_sensitive_headers,
            sensitive_params=_CONFIG.log_sensitive_params,
            sensitive_body_fields=_CONFIG.log_sensitive_body_fields,
        )
        log_activity(
            request,
            logger,
            log_type="generic",
            reason=f"Generic event: {detection_result.trigger_info}",
            level="WARNING",
            sensitive_headers=_CONFIG.log_sensitive_headers,
            sensitive_params=_CONFIG.log_sensitive_params,
            sensitive_body_fields=_CONFIG.log_sensitive_body_fields,
        )

        pipeline_request = case.request_factory(secret)
        pipeline_request.state.client_ip = _PIPELINE_CLIENT_IP
        pipeline_request.state.route_config = None
        pipeline_response = _PIPELINE.execute(pipeline_request)

    assert detection_result.is_threat is True, (
        f"case {case.id!r} never triggered detection - proves nothing"
    )
    assert pipeline_response is not None, (
        f"case {case.id!r} never blocked through the pipeline - "
        "on_block assertion would be vacuous"
    )
    assert secret not in caplog.text, (
        f"case {case.id!r} leaked the secret into a log line: {caplog.text!r}"
    )
    events_dump = _events_dump(_AGENT_RECORDER.events)
    assert secret not in events_dump, (
        f"case {case.id!r} leaked the secret into a SecurityEvent: {events_dump!r}"
    )
    on_block_dump = _on_block_dump(_ON_BLOCK_CALLS)
    assert secret not in on_block_dump, (
        f"case {case.id!r} leaked the secret into the on_block payload: "
        f"{on_block_dump!r}"
    )
    if _otel_sdk_available and _SPAN_EXPORTER is not None:
        spans_dump = _spans_dump(_SPAN_EXPORTER)
        assert secret not in spans_dump, (
            f"case {case.id!r} leaked the secret into an OpenTelemetry span: "
            f"{spans_dump!r}"
        )
