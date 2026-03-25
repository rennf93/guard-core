import json
from collections.abc import Callable, MutableMapping
from typing import Any
from urllib.parse import parse_qs

from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.decorators.base import BaseSecurityMixin
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


class _SimpleResponse:
    def __init__(self, content: str, status_code: int) -> None:
        self._status_code = status_code
        self._headers: dict[str, str] = {}
        self._body = content.encode()

    @property
    def status_code(self) -> int:
        return self._status_code

    @property
    def headers(self) -> MutableMapping[str, str]:
        return self._headers

    @property
    def body(self) -> bytes:
        return self._body


class AdvancedMixin(BaseSecurityMixin):
    def time_window(
        self, start_time: str, end_time: str, timezone: str = "UTC"
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            route_config.time_restrictions = {
                "start": start_time,
                "end": end_time,
                "timezone": timezone,
            }
            return self._apply_route_config(func)

        return decorator

    def suspicious_detection(
        self, enabled: bool = True
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            route_config.enable_suspicious_detection = enabled
            return self._apply_route_config(func)

        return decorator

    def honeypot_detection(
        self, trap_fields: list[str]
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            def honeypot_validator(
                request: SyncGuardRequest,
            ) -> GuardResponse | None:
                def _has_trap_field_filled(data: dict[str, Any]) -> bool:
                    return any(field in data and data[field] for field in trap_fields)

                def _validate_form_data() -> GuardResponse | None:
                    try:
                        raw = (request.body()).decode()
                        parsed = parse_qs(raw)
                        flat = {k: v[0] for k, v in parsed.items() if v}
                        if _has_trap_field_filled(flat):
                            return _SimpleResponse("Forbidden", 403)
                    except Exception:
                        pass
                    return None

                def _validate_json_data() -> GuardResponse | None:
                    try:
                        raw = (request.body()).decode()
                        json_data = json.loads(raw)
                        if _has_trap_field_filled(json_data):
                            return _SimpleResponse("Forbidden", 403)
                    except Exception:
                        pass
                    return None

                if request.method not in ["POST", "PUT", "PATCH"]:
                    return None

                content_type = request.headers.get("content-type", "")

                if "application/x-www-form-urlencoded" in content_type:
                    return _validate_form_data()
                elif "application/json" in content_type:
                    return _validate_json_data()

                return None

            route_config = self._ensure_route_config(func)
            route_config.custom_validators.append(honeypot_validator)
            return self._apply_route_config(func)

        return decorator
