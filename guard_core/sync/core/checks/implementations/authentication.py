from collections.abc import Collection
from typing import Any

from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks._verifier import resolve_verifier_result
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.helpers import extract_credential, route_config_applies
from guard_core.sync.core.events.event_types import EVENT_DECORATOR_VIOLATION
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import log_activity


class AuthenticationCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "authentication"

    @classmethod
    def applies_to(
        cls,
        config: SecurityConfig,
        route_configs: Collection[RouteConfig] | None,
    ) -> bool:
        return route_config_applies(
            route_configs,
            lambda rc: bool(rc.auth_required)
            or bool(rc.api_key_required)
            or bool(rc.authorization_header_required),
        )

    def _handle_auth_failure(
        self,
        request: SyncGuardRequest,
        auth_reason: str,
        route_config: RouteConfig,
        violation_type: str = "require_auth",
    ) -> GuardResponse | None:
        log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Authentication failure: {auth_reason}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
            check_name=self.check_name,
            muted_check_logs=self.config.muted_check_logs,
        )

        self.middleware.event_bus.send_middleware_event(
            event_type=EVENT_DECORATOR_VIOLATION,
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=auth_reason,
            decorator_type="authentication",
            violation_type=violation_type,
            auth_type=route_config.auth_required
            or route_config.authorization_header_required,
        )

        if not self.config.passive_mode:
            return self.middleware.create_error_response(
                status_code=401,
                default_message="Authentication required",
            )

        return None

    def _check_presence(
        self, request: SyncGuardRequest, route_config: RouteConfig, scheme: str
    ) -> GuardResponse | None:
        auth_header = request.headers.get("authorization", "")
        credential, reason = extract_credential(auth_header, scheme)
        if credential is None:
            return self._handle_auth_failure(
                request, reason, route_config, violation_type="authorization_header"
            )
        return None

    def _resolve_credential(
        self, request: SyncGuardRequest, route_config: RouteConfig
    ) -> tuple[GuardResponse | None, Any, str]:
        if route_config.auth_required:
            verifier = route_config.auth_verifier or self.config.auth_verifier
            auth_header = request.headers.get("authorization", "")
            credential, reason = extract_credential(
                auth_header, route_config.auth_required
            )
            if credential is None:
                failure = self._handle_auth_failure(request, reason, route_config)
                return failure, None, ""
            return None, verifier, credential
        verifier = route_config.api_key_verifier or self.config.auth_verifier
        credential = request.headers.get(route_config.api_key_header or "", "")
        if not credential:
            return (
                self._handle_auth_failure(request, "Missing API key", route_config),
                None,
                "",
            )
        return None, verifier, credential

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        route_config = getattr(request.state, "route_config", None)
        if not route_config:
            return None

        presence_scheme = route_config.authorization_header_required
        if presence_scheme:
            return self._check_presence(request, route_config, presence_scheme)

        if not route_config.auth_required and not route_config.api_key_required:
            return None

        failure, verifier, credential = self._resolve_credential(request, route_config)
        if failure is not None:
            return failure

        if verifier is None:
            return self._handle_auth_failure(
                request, "No auth verifier configured", route_config
            )

        try:
            result = resolve_verifier_result(verifier(request, credential))
        except Exception:
            return self._handle_auth_failure(
                request, "Authentication error", route_config
            )
        if not result:
            return self._handle_auth_failure(
                request, "Authentication failed", route_config
            )

        request.state.auth_principal = result
        return None
