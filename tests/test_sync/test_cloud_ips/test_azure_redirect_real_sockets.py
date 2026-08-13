import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from guard_core.sync.handlers.cloud_handler import _download_azure_service_tags

LEGIT_PAYLOAD = {"values": [{"properties": {"addressPrefixes": ["20.20.0.0/16"]}}]}
ATTACKER_PAYLOAD = {"values": [{"properties": {"addressPrefixes": ["203.0.113.0/24"]}}]}


class _RealHttpServer:
    def __init__(self) -> None:
        self.hit_count = 0
        self.handlers: dict[str, tuple[int, dict | None, str | None]] = {}
        self.server = HTTPServer(("127.0.0.1", 0), self._make_request_handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def route_json(self, path: str, payload: dict) -> None:
        self.handlers[path] = (200, payload, None)

    def route_redirect(self, path: str, location: str) -> None:
        self.handlers[path] = (302, None, location)

    def _make_request_handler(self) -> type[BaseHTTPRequestHandler]:
        server = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                status, payload, location = server.handlers.get(
                    self.path, (404, None, None)
                )
                if self.path.endswith("attacker-controlled-payload.json"):
                    server.hit_count += 1
                if status == 302 and location is not None:
                    self.send_response(302)
                    self.send_header("Location", location)
                    self.end_headers()
                    return
                if payload is not None:
                    body = json.dumps(payload).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                pass

        return Handler

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    @property
    def origin(self) -> str:
        port = self.server.server_address[1]
        return f"http://127.0.0.1:{port}"


@pytest.fixture
def attacker_server() -> Iterator[_RealHttpServer]:
    server = _RealHttpServer()
    server.route_json("/attacker-controlled-payload.json", ATTACKER_PAYLOAD)
    server.start()
    try:
        yield server
    finally:
        server.stop()


def test_redirect_to_a_different_origin_is_never_followed(
    attacker_server: _RealHttpServer,
) -> None:
    target = _RealHttpServer()
    target.route_redirect(
        "/download/x/ServiceTags_Public_20250101.json",
        f"{attacker_server.origin}/attacker-controlled-payload.json",
    )
    target.start()
    try:
        trusted_looking_url = (
            f"{target.origin}/download/x/ServiceTags_Public_20250101.json"
        )

        with pytest.raises(ValueError, match="redirect"):
            _download_azure_service_tags(trusted_looking_url)

        assert attacker_server.hit_count == 0
    finally:
        target.stop()


def test_non_redirecting_response_still_downloads_normally() -> None:
    target = _RealHttpServer()
    target.route_json("/download/x/ServiceTags_Public_20250101.json", LEGIT_PAYLOAD)
    target.start()
    try:
        url = f"{target.origin}/download/x/ServiceTags_Public_20250101.json"

        data = _download_azure_service_tags(url)

        assert data == LEGIT_PAYLOAD
    finally:
        target.stop()
