from typing import Any

import pytest

from guard_core.sync.handlers.security_headers_handler import SecurityHeadersManager


def test_csp_report_validation() -> None:
    manager = SecurityHeadersManager()

    valid_report = {
        "csp-report": {
            "document-uri": "https://example.com",
            "violated-directive": "script-src",
            "blocked-uri": "https://evil.com/script.js",
        }
    }
    assert manager.validate_csp_report(valid_report) is True

    invalid_report = {
        "csp-report": {
            "document-uri": "https://example.com",
        }
    }
    assert manager.validate_csp_report(invalid_report) is False

    empty_report: dict[str, Any] = {}
    assert manager.validate_csp_report(empty_report) is False


def test_build_csp_with_empty_sources() -> None:
    manager = SecurityHeadersManager()

    csp_config = {
        "default-src": ["'self'"],
        "script-src": ["'self'", "https://cdn.com"],
        "upgrade-insecure-requests": [],
        "block-all-mixed-content": [],
    }

    csp_header = manager._build_csp(csp_config)

    assert "default-src 'self'" in csp_header
    assert "script-src 'self' https://cdn.com" in csp_header

    assert "upgrade-insecure-requests" in csp_header
    assert "block-all-mixed-content" in csp_header

    assert "upgrade-insecure-requests;" in csp_header or csp_header.endswith(
        "upgrade-insecure-requests"
    )
    assert "block-all-mixed-content;" in csp_header or csp_header.endswith(
        "block-all-mixed-content"
    )


def test_csp_unsafe_inline_warning(caplog: pytest.LogCaptureFixture) -> None:
    manager = SecurityHeadersManager()

    manager.configure(
        csp={
            "script-src": ["'self'", "'unsafe-inline'"],
            "style-src": ["'self'", "'unsafe-eval'"],
        }
    )

    assert "CSP directive 'script-src' contains unsafe sources" in caplog.text
    assert "CSP directive 'style-src' contains unsafe sources" in caplog.text


def test_csp_safe_directives_no_warning(caplog: pytest.LogCaptureFixture) -> None:
    manager = SecurityHeadersManager()

    manager.configure(
        csp={
            "default-src": ["'self'"],
            "script-src": ["'self'", "https://trusted.com"],
            "style-src": ["'self'", "'nonce-abc123'"],
        }
    )

    assert "unsafe sources" not in caplog.text
