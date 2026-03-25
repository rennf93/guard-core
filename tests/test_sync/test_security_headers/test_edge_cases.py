from collections.abc import Generator

import pytest

from guard_core.sync.handlers.security_headers_handler import (
    SecurityHeadersManager,
    reset_global_state,
)


@pytest.fixture
def headers_manager() -> Generator[SecurityHeadersManager, None]:
    reset_global_state()
    yield SecurityHeadersManager()
    reset_global_state()


def test_reset_global_state() -> None:
    original_instance = SecurityHeadersManager._instance

    try:
        SecurityHeadersManager._instance = None

        manager = SecurityHeadersManager()
        manager.custom_headers = {"X-Test": "value"}
        manager.enabled = False

        SecurityHeadersManager._instance = None

        reset_global_state()

        from guard_core.sync.handlers.security_headers_handler import (
            security_headers_manager as new_manager,
        )

        assert new_manager.enabled is True
        assert len(new_manager.custom_headers) == 0

    finally:
        SecurityHeadersManager._instance = original_instance


def test_get_headers_with_cached_non_dict_value(
    headers_manager: SecurityHeadersManager,
) -> None:
    headers_manager.enabled = True

    cache_key = headers_manager._generate_cache_key("test_path")

    headers_manager.headers_cache[cache_key] = "invalid_value"

    headers = headers_manager.get_headers("test_path")

    assert isinstance(headers, dict)
    assert "X-Content-Type-Options" in headers
    assert "X-Frame-Options" in headers

    assert isinstance(headers_manager.headers_cache[cache_key], dict)


def test_complete_secure_configuration() -> None:
    manager = SecurityHeadersManager()

    manager.configure(
        csp={
            "default-src": ["'self'"],
            "script-src": ["'self'", "https://cdn.example.com"],
            "style-src": ["'self'", "'nonce-abc123'"],
        },
        hsts_max_age=63072000,
        hsts_include_subdomains=True,
        hsts_preload=True,
        cors_origins=["https://app.example.com"],
        cors_allow_credentials=True,
        custom_headers={
            "X-Custom-Security": "enabled",
            "X-Request-ID": "123456",
        },
    )

    headers = manager.get_headers("/api/endpoint")

    assert "Content-Security-Policy" in headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]

    assert "Strict-Transport-Security" in headers
    hsts = headers["Strict-Transport-Security"]
    assert "max-age=63072000" in hsts
    assert "includeSubDomains" in hsts
    assert "preload" in hsts

    assert headers["X-Custom-Security"] == "enabled"
    assert headers["X-Request-ID"] == "123456"

    cors_headers = manager.get_cors_headers("https://app.example.com")
    assert cors_headers["Access-Control-Allow-Origin"] == "https://app.example.com"
    assert cors_headers["Access-Control-Allow-Credentials"] == "true"
