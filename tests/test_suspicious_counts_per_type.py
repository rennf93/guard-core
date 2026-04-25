import inspect

from guard_core.protocols.middleware_protocol import GuardMiddlewareProtocol


def test_protocol_raw_annotation_is_nested_dict() -> None:
    raw = GuardMiddlewareProtocol.__annotations__["suspicious_request_counts"]
    assert raw == "dict[str, dict[str, int]]"


def test_protocol_source_uses_nested_dict() -> None:
    source = inspect.getsource(GuardMiddlewareProtocol)
    assert "suspicious_request_counts: dict[str, dict[str, int]]" in source
