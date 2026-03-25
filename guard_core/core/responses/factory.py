from collections.abc import Awaitable, Callable

from guard_core.core.responses.context import ResponseContext
from guard_core.decorators.base import RouteConfig
from guard_core.handlers.security_headers_handler import security_headers_manager
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import extract_client_ip


class ErrorResponseFactory:
    def __init__(self, context: ResponseContext):
        self.context = context

    async def create_error_response(
        self, status_code: int, default_message: str
    ) -> GuardResponse:
        custom_message = self.context.config.custom_error_responses.get(
            status_code, default_message
        )
        response: GuardResponse = self.context.response_factory.create_response(
            custom_message, status_code
        )

        response = await self.apply_security_headers(response)

        response = await self.apply_modifier(response)

        return response

    async def create_https_redirect(self, request: GuardRequest) -> GuardResponse:
        https_url = request.url_replace_scheme("https")
        redirect_response = self.context.response_factory.create_redirect_response(
            str(https_url), 301
        )

        return await self.apply_modifier(redirect_response)

    async def apply_security_headers(
        self, response: GuardResponse, request_path: str | None = None
    ) -> GuardResponse:
        headers_config = self.context.config.security_headers
        if headers_config and headers_config.get("enabled", True):
            security_headers = await security_headers_manager.get_headers(request_path)
            for header_name, header_value in security_headers.items():
                response.headers[header_name] = header_value

        return response

    async def apply_cors_headers(
        self, response: GuardResponse, origin: str
    ) -> GuardResponse:
        headers_config = self.context.config.security_headers
        if headers_config and headers_config.get("enabled", True):
            cors_headers = await security_headers_manager.get_cors_headers(origin)
            for header_name, header_value in cors_headers.items():
                response.headers[header_name] = header_value

        return response

    async def apply_modifier(self, response: GuardResponse) -> GuardResponse:
        if self.context.config.custom_response_modifier:
            result: GuardResponse = await self.context.config.custom_response_modifier(
                response
            )
            return result
        return response

    async def process_response(
        self,
        request: GuardRequest,
        response: GuardResponse,
        response_time: float,
        route_config: RouteConfig | None,
        process_behavioral_rules: Callable[
            [GuardRequest, GuardResponse, str, RouteConfig], Awaitable[None]
        ]
        | None = None,
    ) -> GuardResponse:
        if route_config and route_config.behavior_rules and process_behavioral_rules:
            client_ip = await extract_client_ip(
                request, self.context.config, self.context.agent_handler
            )
            await process_behavioral_rules(request, response, client_ip, route_config)

        await self.context.metrics_collector.collect_request_metrics(
            request, response_time, response.status_code
        )

        response = await self.apply_security_headers(response, str(request.url_path))

        origin = request.headers.get("origin")
        if origin:
            response = await self.apply_cors_headers(response, origin)

        return await self.apply_modifier(response)
