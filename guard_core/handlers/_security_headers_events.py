import logging
from datetime import datetime, timezone
from typing import Any


class SecurityHeadersEventsMixin:
    agent_handler: Any
    logger: logging.Logger

    async def initialize_agent(self, agent_handler: Any) -> None:
        self.agent_handler = agent_handler

    async def _send_headers_applied_event(
        self, path: str, headers: dict[str, str]
    ) -> None:
        from guard_core.core.events.event_types import EVENT_SECURITY_HEADERS_APPLIED

        try:
            from guard_core._pydantic_plugin_mute import get_telemetry_model

            SecurityEvent = get_telemetry_model("SecurityEvent")

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=EVENT_SECURITY_HEADERS_APPLIED,
                action_taken="headers_added",
                metadata={
                    "path": path,
                    "headers_count": len(headers),
                    "has_csp": "Content-Security-Policy" in headers,
                    "has_hsts": "Strict-Transport-Security" in headers,
                },
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.debug(f"Failed to send headers event to agent: {e}")

    async def validate_csp_report(self, report: dict[str, Any]) -> bool:
        required_fields = ["document-uri", "violated-directive", "blocked-uri"]

        csp_report = report.get("csp-report", {})
        if not all(field in csp_report for field in required_fields):
            return False

        self.logger.warning(
            f"CSP Violation: {csp_report.get('violated-directive')} "
            f"blocked {csp_report.get('blocked-uri')} "
            f"on {csp_report.get('document-uri')}"
        )

        if self.agent_handler:
            await self._send_csp_violation_event(csp_report)

        return True

    async def _send_csp_violation_event(self, report: dict[str, Any]) -> None:
        from guard_core.core.events.event_types import EVENT_CSP_VIOLATION

        try:
            from guard_core._pydantic_plugin_mute import get_telemetry_model

            SecurityEvent = get_telemetry_model("SecurityEvent")

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=EVENT_CSP_VIOLATION,
                action_taken="logged",
                metadata={
                    "document_uri": report.get("document-uri"),
                    "violated_directive": report.get("violated-directive"),
                    "blocked_uri": report.get("blocked-uri"),
                    "source_file": report.get("source-file"),
                    "line_number": report.get("line-number"),
                },
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.debug(f"Failed to send CSP violation event to agent: {e}")
