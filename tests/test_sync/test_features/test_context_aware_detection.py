from collections.abc import Iterator
from typing import Any

import pytest

from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager


@pytest.fixture(autouse=True)
def reset_manager() -> Iterator[None]:
    old_instance: Any = SusPatternsManager._instance
    SusPatternsManager._instance = None
    yield
    SusPatternsManager._instance = old_instance


def test_normalize_context_strips_suffix() -> None:
    assert SusPatternsManager._normalize_context("query_param:search") == "query_param"
    assert SusPatternsManager._normalize_context("header:X-Custom") == "header"
    assert SusPatternsManager._normalize_context("url_path") == "url_path"


def test_normalize_context_unknown_for_unrecognized() -> None:
    assert SusPatternsManager._normalize_context("test") == "unknown"
    assert SusPatternsManager._normalize_context("foobar") == "unknown"
    assert SusPatternsManager._normalize_context("") == "unknown"


def test_sqli_fires_on_query_param() -> None:
    manager = SusPatternsManager()
    result = manager.detect(
        "SELECT * FROM users",
        "127.0.0.1",
        context="query_param:id",
    )
    assert result["is_threat"] is True


def test_sqli_does_not_fire_on_url_path() -> None:
    manager = SusPatternsManager()
    result = manager.detect(
        "SELECT * FROM users",
        "127.0.0.1",
        context="url_path",
    )
    assert result["is_threat"] is False


def test_sensitive_file_fires_on_url_path() -> None:
    manager = SusPatternsManager()
    result = manager.detect(
        "/.env",
        "127.0.0.1",
        context="url_path",
    )
    assert result["is_threat"] is True


def test_sensitive_file_does_not_fire_on_query_param() -> None:
    manager = SusPatternsManager()
    result = manager.detect(
        "/.env",
        "127.0.0.1",
        context="query_param:file",
    )
    assert result["is_threat"] is False


def test_all_patterns_fire_on_unknown() -> None:
    manager = SusPatternsManager()
    sqli_result = manager.detect(
        "SELECT * FROM users",
        "127.0.0.1",
        context="unknown",
    )
    assert sqli_result["is_threat"] is True

    env_result = manager.detect(
        "/.env",
        "127.0.0.1",
        context="unknown",
    )
    assert env_result["is_threat"] is True


def test_all_patterns_fire_on_request_body() -> None:
    manager = SusPatternsManager()
    result = manager.detect(
        "SELECT * FROM users",
        "127.0.0.1",
        context="request_body",
    )
    assert result["is_threat"] is True


def test_custom_patterns_fire_on_all_contexts() -> None:
    manager = SusPatternsManager()
    manager.add_pattern(r"custom_evil_\d+", custom=True)

    for ctx in ["query_param", "header", "url_path", "request_body", "unknown"]:
        result = manager.detect(
            "custom_evil_123",
            "127.0.0.1",
            context=ctx,
        )
        assert result["is_threat"] is True, f"Custom pattern failed for context: {ctx}"


def test_xss_fires_on_header() -> None:
    manager = SusPatternsManager()
    result = manager.detect(
        "<script>alert(1)</script>",
        "127.0.0.1",
        context="header:X-Custom",
    )
    assert result["is_threat"] is True


def test_xml_injection_fires_on_header() -> None:
    manager = SusPatternsManager()
    result = manager.detect(
        '<!ENTITY xxe SYSTEM "file:///etc/passwd">',
        "127.0.0.1",
        context="header:Content-Type",
    )
    assert result["is_threat"] is True


def test_xml_injection_does_not_fire_on_url_path() -> None:
    manager = SusPatternsManager()
    result = manager.detect(
        "<![CDATA[malicious]]>",
        "127.0.0.1",
        context="url_path",
    )
    assert result["is_threat"] is False
