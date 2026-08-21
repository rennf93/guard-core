import logging
from typing import Any


class SecurityHeadersCorsMixin:
    logger: logging.Logger
    cors_config: dict[str, Any] | None

    def _is_wildcard_with_credentials(self, allowed_origins: list[str]) -> bool:
        if "*" not in allowed_origins:
            return False

        if self.cors_config and self.cors_config.get("allow_credentials"):
            self.logger.warning(
                "Credentials cannot be used with wildcard origin - blocking CORS"
            )
            return True

        return False

    def _is_origin_allowed(self, origin: str, allowed_origins: list[str]) -> bool:
        return "*" in allowed_origins or origin in allowed_origins

    def _get_validated_cors_config(self) -> tuple[list[str], list[str]]:
        if not self.cors_config:
            return ["GET", "POST"], ["*"]

        allow_methods = self.cors_config.get("allow_methods", ["GET", "POST"])
        allow_headers = self.cors_config.get("allow_headers", ["*"])

        if not isinstance(allow_methods, list):
            allow_methods = ["GET", "POST"]
        if not isinstance(allow_headers, list):
            allow_headers = ["*"]

        return allow_methods, allow_headers

    def _build_cors_headers(
        self,
        origin: str,
        allowed_origins: list[str],
        allow_methods: list[str],
        allow_headers: list[str],
    ) -> dict[str, str]:
        cors_headers = {
            "Access-Control-Allow-Origin": origin if origin in allowed_origins else "*",
            "Access-Control-Allow-Methods": ", ".join(allow_methods),
            "Access-Control-Allow-Headers": ", ".join(allow_headers),
            "Access-Control-Max-Age": "3600",
        }

        if self.cors_config and self.cors_config.get("allow_credentials"):
            cors_headers["Access-Control-Allow-Credentials"] = "true"

        return cors_headers

    def get_cors_headers(self, origin: str) -> dict[str, str]:
        if not self.cors_config:
            return {}

        allowed_origins = self.cors_config.get("origins", [])
        if not isinstance(allowed_origins, list):
            return {}

        if self._is_wildcard_with_credentials(allowed_origins):
            return {}

        if not self._is_origin_allowed(origin, allowed_origins):
            return {}

        allow_methods, allow_headers = self._get_validated_cors_config()
        return self._build_cors_headers(
            origin, allowed_origins, allow_methods, allow_headers
        )
