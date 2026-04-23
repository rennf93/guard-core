from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from guard_core.core.checks.base import SecurityCheck
from guard_core.core.events.event_types import EVENT_DECORATOR_VIOLATION
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import log_activity


class TimeWindowCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "time_window"

    async def _check_time_window(self, time_restrictions: dict[str, str]) -> bool:
        try:
            start_time = time_restrictions["start"]
            end_time = time_restrictions["end"]

            timezone_str = time_restrictions.get("timezone", "UTC")
            try:
                tz: ZoneInfo | timezone = ZoneInfo(timezone_str)
            except (KeyError, Exception):
                tz = timezone.utc
            current_time = datetime.now(tz)
            current_hour_minute = current_time.strftime("%H:%M")

            if start_time > end_time:
                return (
                    current_hour_minute >= start_time or current_hour_minute <= end_time
                )
            else:
                return start_time <= current_hour_minute <= end_time

        except Exception as e:
            self.logger.error(f"Error checking time window: {str(e)}")
            return True

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        route_config = getattr(request.state, "route_config", None)
        if not route_config or not route_config.time_restrictions:
            return None

        time_allowed = await self._check_time_window(route_config.time_restrictions)
        if not time_allowed:
            await log_activity(
                request,
                self.logger,
                log_type="suspicious",
                reason="Access outside allowed time window",
                level=self.config.log_suspicious_level,
                passive_mode=self.config.passive_mode,
                check_name=self.check_name,
                muted_check_logs=self.config.muted_check_logs,
            )
            await self.middleware.event_bus.send_middleware_event(
                event_type=EVENT_DECORATOR_VIOLATION,
                request=request,
                action_taken="request_blocked"
                if not self.config.passive_mode
                else "logged_only",
                reason="Access outside allowed time window",
                decorator_type="advanced",
                violation_type="time_restriction",
            )
            if not self.config.passive_mode:
                return await self.middleware.create_error_response(
                    status_code=403,
                    default_message="Access not allowed at this time",
                )
        return None
