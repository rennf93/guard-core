import json
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

from tests.redaction_gate.axes import EXCLUDED_HEADER_NAME


def _request_cls(mod: Any) -> Any:
    return getattr(mod, "MockGuardRequest", None) or mod.SyncMockGuardRequest


def _plain_body_request(mod: Any, body: bytes, content_type: str) -> Any:
    return _request_cls(mod)(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers={"content-type": content_type, "content-length": str(len(body))},
    )


def _multipart_filename_request(mod: Any, blob: str) -> Any:
    builder = getattr(mod, "_multipart_filename_body_request", None)
    if builder is not None:
        return builder("upload", blob)
    body = (
        f'--B0\r\nContent-Disposition: form-data; name="upload"; filename="{blob}"'
        f"\r\n\r\nbinary-content\r\n--B0--\r\n"
    ).encode()
    return _plain_body_request(mod, body, mod._CONTENT_TYPE_MULTIPART)


def _multipart_filename_and_text_request(mod: Any, blob: str) -> Any:
    body = (
        f'--B0\r\nContent-Disposition: form-data; name="upload"; filename="{blob}"'
        f"\r\n\r\n{blob}\r\n--B0--\r\n"
    ).encode()
    return _plain_body_request(mod, body, mod._CONTENT_TYPE_MULTIPART)


def _json_array_body(blob: str, wrap_levels: int) -> bytes:
    node: Any = [{"leaf": {"note": blob}}]
    for _ in range(max(0, wrap_levels)):
        node = {"wrapper": node}
    return json.dumps(node).encode()


def _json_deep_request(mod: Any, blob: str) -> Any:
    depth = max(1, mod._json_depth_cap_value() - 1)
    return mod._json_body_request(
        mod._nested_wrapper_body(depth, "wrapper", {"note": blob})
    )


def _json_array_deep_request(mod: Any, blob: str) -> Any:
    depth = max(1, mod._json_depth_cap_value() - 3)
    return mod._json_body_request(_json_array_body(blob, depth))


def _json_in_query_pct_encoded_request(mod: Any, blob: str) -> Any:
    return mod._query_request("data", quote(json.dumps({"note": blob}), safe=""))


_SURFACE_BUILDERS: dict[str, Callable[[Any, str], Any]] = {
    "header": lambda mod, blob: mod._header_request("X-Session", blob),
    "cookie_header": lambda mod, blob: mod._header_request("Cookie", blob),
    "excluded_header": lambda mod, blob: mod._header_request(
        EXCLUDED_HEADER_NAME, blob
    ),
    "query_param": lambda mod, blob: mod._query_request("data", blob),
    "url_query_string": lambda mod, blob: mod._encoded_query_path_request(blob),
    "url_fragment": lambda mod, blob: mod._path_request(f"/route#{blob}"),
    "url_path_segment": lambda mod, blob: mod._path_request(f"/{blob}"),
    "matrix_param": lambda mod, blob: mod._path_request(f"/resource;{blob}"),
    "form_field": lambda mod, blob: mod._form_body_request({"note": blob}),
    "multipart_text": lambda mod, blob: mod._multipart_body_request("note", blob),
    "multipart_filename": _multipart_filename_request,
    "multipart_filename_and_text": _multipart_filename_and_text_request,
    "json_shallow": lambda mod, blob: mod._json_body_request(
        json.dumps({"note": blob}).encode()
    ),
    "json_deep": _json_deep_request,
    "json_array_shallow": lambda mod, blob: mod._json_body_request(
        _json_array_body(blob, 1)
    ),
    "json_array_deep": _json_array_deep_request,
    "json_in_header": lambda mod, blob: mod._header_request(
        "X-Info", json.dumps({"note": blob})
    ),
    "json_in_query": lambda mod, blob: mod._query_request(
        "data", json.dumps({"note": blob})
    ),
    "json_in_query_pct_encoded": _json_in_query_pct_encoded_request,
    "text_plain": lambda mod, blob: _plain_body_request(
        mod, blob.encode(), "text/plain"
    ),
    "xml_body": lambda mod, blob: _plain_body_request(
        mod, f"<root>{blob}</root>".encode(), "application/xml"
    ),
}


def build_request_for_surface(mod: Any, surface: str, blob: str) -> Any:
    try:
        builder = _SURFACE_BUILDERS[surface]
    except KeyError as exc:
        raise ValueError(f"unknown surface {surface!r}") from exc
    return builder(mod, blob)
