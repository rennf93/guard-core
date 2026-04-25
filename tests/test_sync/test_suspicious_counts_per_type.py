import inspect

from guard_core.sync.protocols.middleware_protocol import SyncGuardMiddlewareProtocol


def test_protocol_raw_annotation_is_nested_dict() -> None:
    raw = SyncGuardMiddlewareProtocol.__annotations__["suspicious_request_counts"]
    assert raw == "dict[str, dict[str, int]]"


def test_protocol_source_uses_nested_dict() -> None:
    source = inspect.getsource(SyncGuardMiddlewareProtocol)
    assert "suspicious_request_counts: dict[str, dict[str, int]]" in source
