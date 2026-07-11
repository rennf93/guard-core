from typing import Any

from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.implementations import (
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
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline

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


def build_default_pipeline(middleware: Any) -> SecurityCheckPipeline:
    return SecurityCheckPipeline([cls(middleware) for cls in DEFAULT_CHECK_CLASSES])
