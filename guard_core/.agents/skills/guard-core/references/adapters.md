# Adapters

Implement three protocols to bridge a framework into the guard-core pipeline. Everything else (checks, detection, Redis, telemetry) works out of the box.

## GuardRequest

```python
from guard_core.protocols import GuardRequest


class MyFrameworkRequest:
    def __init__(self, native_request):
        self._request = native_request

    @property
    def url_path(self) -> str:
        return self._request.path

    @property
    def url_scheme(self) -> str:
        return self._request.scheme

    @property
    def url_full(self) -> str:
        return str(self._request.url)

    def url_replace_scheme(self, scheme: str) -> str:
        return self.url_full.replace(f"{self.url_scheme}://", f"{scheme}://", 1)

    @property
    def method(self) -> str:
        return self._request.method

    @property
    def client_host(self) -> str | None:
        return self._request.remote_addr

    @property
    def headers(self):
        return dict(self._request.headers)

    @property
    def query_params(self):
        return dict(self._request.args)

    async def body(self) -> bytes:
        return await self._request.body()

    @property
    def state(self):
        return self._request.state

    @property
    def scope(self) -> dict:
        return self._request.scope
```

## GuardResponse / GuardResponseFactory

```python
from guard_core.protocols import GuardResponse, GuardResponseFactory


class MyFrameworkResponse:
    def __init__(self, status_code: int, headers: dict, body: bytes | None):
        self._status_code = status_code
        self._headers = headers
        self._body = body

    @property
    def status_code(self) -> int:
        return self._status_code

    @property
    def headers(self):
        return self._headers

    @property
    def body(self) -> bytes | None:
        return self._body


class MyFrameworkResponseFactory:
    @staticmethod
    def create_response(content: str, status_code: int) -> GuardResponse:
        return MyFrameworkResponse(
            status_code,
            {"content-type": "application/json"},
            content.encode(),
        )

    @staticmethod
    def create_redirect_response(url: str, status_code: int) -> GuardResponse:
        return MyFrameworkResponse(status_code, {"location": url}, None)
```

## Middleware wiring

Adapters build the event bus, metrics collector, and composite handler through `HandlerInitializer.initialize_agent_integrations()` so the composite agent handler and event filter are wired automatically. An adapter that bypasses the initializer must construct the `CompositeAgentHandler` and install it as the `agent_handler` on the event bus and metrics collector, or mute and enrichment will not apply uniformly.

The pipeline is constructed with the ordered list of `SecurityCheck` instances; `SecurityCheckPipeline(checks)` does not accept `muted_check_logs` in the shipping adapters, so pipeline-level block/error log lines are not muted in practice even when `muted_check_logs` is set (the in-check `log_activity()` calls are muted).
