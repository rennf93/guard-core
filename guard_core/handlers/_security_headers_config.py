import logging
from typing import Any


class SecurityHeadersConfigMixin:
    logger: logging.Logger
    enabled: bool
    custom_headers: dict[str, str]
    csp_config: dict[str, list[str]] | None
    hsts_config: dict[str, Any] | None
    cors_config: dict[str, Any] | None
    default_headers: dict[str, str]

    def _validate_header_value(self, value: str) -> str:
        if "\r" in value or "\n" in value:
            raise ValueError(f"Invalid header value contains newline: {value}")
        if len(value) > 8192:
            raise ValueError(f"Header value too long: {len(value)} bytes")
        sanitized = "".join(char for char in value if ord(char) >= 32 or char == "\t")
        return sanitized

    def _configure_csp(self, csp: dict[str, list[str]] | None) -> None:
        if not csp:
            return

        self.csp_config = csp
        for directive, sources in csp.items():
            if "'unsafe-inline'" in sources or "'unsafe-eval'" in sources:
                self.logger.warning(
                    f"CSP directive '{directive}' contains unsafe sources"
                )

    def _configure_hsts(
        self,
        hsts_max_age: int | None,
        hsts_include_subdomains: bool,
        hsts_preload: bool,
    ) -> None:
        if hsts_max_age is None:
            return

        if hsts_preload:
            if hsts_max_age < 31536000:
                self.logger.warning("HSTS preload requires max_age >= 31536000")
                hsts_preload = False
            if not hsts_include_subdomains:
                self.logger.warning("HSTS preload requires includeSubDomains")
                hsts_include_subdomains = True

        self.hsts_config = {
            "max_age": hsts_max_age,
            "include_subdomains": hsts_include_subdomains,
            "preload": hsts_preload,
        }

    def _configure_cors(
        self,
        cors_origins: list[str] | None,
        cors_allow_credentials: bool,
        cors_allow_methods: list[str] | None,
        cors_allow_headers: list[str] | None,
    ) -> None:
        if not cors_origins:
            return

        if "*" in cors_origins and cors_allow_credentials:
            self.logger.error(
                "CORS config error: Wildcard origin disallowed with credentials"
            )
            cors_allow_credentials = False

        self.cors_config = {
            "origins": cors_origins,
            "allow_credentials": cors_allow_credentials,
            "allow_methods": cors_allow_methods or ["GET", "POST"],
            "allow_headers": cors_allow_headers or ["*"],
        }

    def _update_default_headers(
        self,
        frame_options: str | None,
        content_type_options: str | None,
        xss_protection: str | None,
        referrer_policy: str | None,
        permissions_policy: str | None,
    ) -> None:
        if frame_options is not None:
            self.default_headers["X-Frame-Options"] = self._validate_header_value(
                frame_options
            )
        if content_type_options is not None:
            self.default_headers["X-Content-Type-Options"] = (
                self._validate_header_value(content_type_options)
            )
        if xss_protection is not None:
            self.default_headers["X-XSS-Protection"] = self._validate_header_value(
                xss_protection
            )
        if referrer_policy is not None:
            self.default_headers["Referrer-Policy"] = self._validate_header_value(
                referrer_policy
            )
        if permissions_policy != "UNSET":
            if permissions_policy:
                self.default_headers["Permissions-Policy"] = (
                    self._validate_header_value(permissions_policy)
                )
            else:
                self.default_headers.pop("Permissions-Policy", None)

    def _add_custom_headers(self, custom_headers: dict[str, str] | None) -> None:
        if not custom_headers:
            return

        for name, value in custom_headers.items():
            self.custom_headers[name] = self._validate_header_value(value)

    def configure(
        self,
        *,
        enabled: bool = True,
        csp: dict[str, list[str]] | None = None,
        hsts_max_age: int | None = None,
        hsts_include_subdomains: bool = True,
        hsts_preload: bool = False,
        frame_options: str | None = None,
        content_type_options: str | None = None,
        xss_protection: str | None = None,
        referrer_policy: str | None = None,
        permissions_policy: str | None = "UNSET",
        custom_headers: dict[str, str] | None = None,
        cors_origins: list[str] | None = None,
        cors_allow_credentials: bool = False,
        cors_allow_methods: list[str] | None = None,
        cors_allow_headers: list[str] | None = None,
    ) -> None:
        self.enabled = enabled

        self._configure_csp(csp)
        self._configure_hsts(hsts_max_age, hsts_include_subdomains, hsts_preload)
        self._configure_cors(
            cors_origins, cors_allow_credentials, cors_allow_methods, cors_allow_headers
        )
        self._update_default_headers(
            frame_options,
            content_type_options,
            xss_protection,
            referrer_policy,
            permissions_policy,
        )
        self._add_custom_headers(custom_headers)
