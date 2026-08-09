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

Build the pipeline through `guard_core.core.checks.build_default_pipeline(middleware)` rather than hand-listing check classes; it passes `config.muted_check_logs` into `SecurityCheckPipeline`, so both pipeline-level block/error log lines and the in-check `log_activity()` calls honor `muted_check_logs`.

`build_default_pipeline` also filters the check catalogue through each check's `applies_to(config, route_configs)`. Route configuration reaches that filter only through `getattr(middleware, "guard_decorator", None)`, which is not part of `GuardMiddlewareProtocol` and so is optional; when it is absent or `None`, `route_configs` is `None` and every check whose predicate consults route configuration is kept rather than dropped. An adapter that cannot expose `guard_decorator` therefore loses the build-time elimination for those route-driven checks specifically (checks gated purely by global `SecurityConfig` flags are unaffected either way), but the protection is identical in both cases: build the pipeline (or rebuild it) after the application has registered its routes and attached its `SecurityDecorator`, and expose that decorator instance as `middleware.guard_decorator`, to get the smaller pipeline. See [the pipeline reference](pipeline.md#which-checks-get-built) for the full elimination mechanism.
