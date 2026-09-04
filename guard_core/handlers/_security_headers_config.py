import logging
import re
from typing import Any

from cachetools import TTLCache


class SecurityHeadersConfigMixin:
    logger: logging.Logger
    enabled: bool
    custom_headers: dict[str, str]
    csp_config: dict[str, list[str]] | None
    hsts_config: dict[str, Any] | None
    cors_config: dict[str, Any] | None
    default_headers: dict[str, str]
    headers_cache: TTLCache

    _HEADER_NAME_TOKEN_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")

    def _validate_header_name(self, name: str) -> str:
        if not self._HEADER_NAME_TOKEN_RE.fullmatch(name):
            raise ValueError(f"Invalid header name: {name}")
        return name

    def _validate_header_value(self, value: str) -> str:
        if "\r" in value or "\n" in value:
            raise ValueError(f"Invalid header value contains newline: {value}")
        if len(value) > 8192:
            raise ValueError(f"Header value too long: {len(value)} bytes")
        sanitized = "".join(char for char in value if ord(char) >= 32 or char == "\t")
        return sanitized

    def _configure_csp(self, csp: dict[str, list[str]] | None) -> None:
        if not csp:
            self.csp_config = None
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
            self.hsts_config = None
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
            self.cors_config = None
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

    def _reset_or_apply_header(
        self, header_name: str, override: str | None, class_default: str
    ) -> None:
        self.default_headers[header_name] = (
            self._validate_header_value(override)
            if override is not None
            else class_default
        )

    def _update_default_headers(
        self,
        frame_options: str | None,
        content_type_options: str | None,
        xss_protection: str | None,
        referrer_policy: str | None,
        permissions_policy: str | None,
    ) -> None:
        class_defaults = self.__class__.default_headers
        self._reset_or_apply_header(
            "X-Frame-Options", frame_options, class_defaults["X-Frame-Options"]
        )
        self._reset_or_apply_header(
            "X-Content-Type-Options",
            content_type_options,
            class_defaults["X-Content-Type-Options"],
        )
        self._reset_or_apply_header(
            "X-XSS-Protection", xss_protection, class_defaults["X-XSS-Protection"]
        )
        self._reset_or_apply_header(
            "Referrer-Policy", referrer_policy, class_defaults["Referrer-Policy"]
        )

        if permissions_policy == "UNSET":
            self.default_headers["Permissions-Policy"] = class_defaults[
                "Permissions-Policy"
            ]
        elif permissions_policy:
            self.default_headers["Permissions-Policy"] = self._validate_header_value(
                permissions_policy
            )
        else:
            self.default_headers.pop("Permissions-Policy", None)

    def _add_custom_headers(self, custom_headers: dict[str, str] | None) -> None:
        self.custom_headers = {}
        if not custom_headers:
            return

        for name, value in custom_headers.items():
            validated_name = self._validate_header_name(name)
            self.custom_headers[validated_name] = self._validate_header_value(value)

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
        self.headers_cache.clear()

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
