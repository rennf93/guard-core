from typing import TYPE_CHECKING

from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.implementations import (
    AuthenticationCheck,
    CloudIpRefreshCheck,
    CloudProviderCheck,
    CustomRequestCheck,
    CustomValidatorsCheck,
    EmergencyModeCheck,
    HttpsEnforcementCheck,
    IpSecurityCheck,
    RateLimitCheck,
    ReferrerCheck,
    RequestLoggingCheck,
    RequestSizeContentCheck,
    RequiredHeadersCheck,
    RouteConfigCheck,
    SuspiciousActivityCheck,
    TimeWindowCheck,
    UserAgentCheck,
)
from guard_core.core.checks.pipeline import SecurityCheckPipeline

if TYPE_CHECKING:
    from guard_core.protocols.middleware_protocol import GuardMiddlewareProtocol

DEFAULT_CHECK_CLASSES: tuple[type[SecurityCheck], ...] = (
    RouteConfigCheck,
    EmergencyModeCheck,
    HttpsEnforcementCheck,
    RequestLoggingCheck,
    RequestSizeContentCheck,
    RequiredHeadersCheck,
    AuthenticationCheck,
    ReferrerCheck,
    CustomValidatorsCheck,
    TimeWindowCheck,
    CloudIpRefreshCheck,
    IpSecurityCheck,
    CloudProviderCheck,
    UserAgentCheck,
    RateLimitCheck,
    SuspiciousActivityCheck,
    CustomRequestCheck,
)


def build_default_pipeline(
    middleware: "GuardMiddlewareProtocol",
) -> SecurityCheckPipeline:
    return SecurityCheckPipeline(
        [cls(middleware) for cls in DEFAULT_CHECK_CLASSES],
        muted_check_logs=middleware.config.muted_check_logs,
    )
