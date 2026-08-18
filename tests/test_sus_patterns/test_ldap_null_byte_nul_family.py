from collections.abc import Generator

import pytest

from guard_core.handlers.suspatterns_handler import (
    _LDAP_NULL_BYTE_ATTR_RE,
    _LDAP_NULL_BYTE_BARE_RE,
    _LDAP_NULL_BYTE_DECODED_ATTR_RE,
    _LDAP_NULL_BYTE_DECODED_BARE_RE,
    DETECTION_RAW_VIEW_PATTERN_SOURCES,
    DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES,
    SusPatternsManager,
    sus_patterns_handler,
)
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

_NUL_RAW = chr(0)
_NUL_UNICODE_TEXT = chr(92) + "u0000"
_NUL_HEX_TEXT = chr(92) + "x00"
_NUL_OCTAL_TEXT = chr(92) + "0"


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


@pytest.fixture
def manager() -> Generator[SusPatternsManager, None, None]:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    new_instance = SusPatternsManager(SecurityConfig())
    yield new_instance
    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config


def _body_request(body: str) -> MockGuardRequest:
    encoded = body.encode()
    return MockGuardRequest(
        path="/login",
        method="POST",
        headers={"content-length": str(len(encoded))},
        body_content=encoded,
    )


async def _body_categories(body: str) -> list[str]:
    result = await detect_penetration_attempt(_body_request(body), SecurityConfig())
    return list(result.threat_categories)


async def _body_is_threat(body: str) -> bool:
    result = await detect_penetration_attempt(_body_request(body), SecurityConfig())
    return bool(result.is_threat)


async def _manager_detect(body: str, manager: SusPatternsManager) -> dict:
    return await manager.detect(body, "203.0.113.9", context="request_body")


_LDAP_NULL_BYTE_PATTERNS = frozenset(
    {
        _LDAP_NULL_BYTE_ATTR_RE,
        _LDAP_NULL_BYTE_BARE_RE,
        _LDAP_NULL_BYTE_DECODED_ATTR_RE,
        _LDAP_NULL_BYTE_DECODED_BARE_RE,
    }
)


def _null_byte_threats(result: dict) -> list[dict]:
    return [
        threat
        for threat in result["threats"]
        if threat.get("type") == "regex"
        and threat.get("pattern") in _LDAP_NULL_BYTE_PATTERNS
    ]


LDAP_NUL_FAMILY_BODIES = [
    pytest.param("uid=alice*)" + _NUL_RAW, id="attr_raw_nul_byte"),
    pytest.param("*)" + ")" + _NUL_RAW, id="bare_raw_nul_byte"),
    pytest.param("uid=alice*)" + _NUL_UNICODE_TEXT, id="attr_literal_unicode_nul_text"),
    pytest.param("*)" + ")" + _NUL_UNICODE_TEXT, id="bare_literal_unicode_nul_text"),
    pytest.param("uid=alice*)" + _NUL_HEX_TEXT, id="attr_literal_hex_nul_text"),
    pytest.param("*)" + ")" + _NUL_HEX_TEXT, id="bare_literal_hex_nul_text"),
    pytest.param("uid=alice*)" + _NUL_OCTAL_TEXT, id="attr_literal_octal_nul_text"),
    pytest.param("*)" + ")" + _NUL_OCTAL_TEXT, id="bare_literal_octal_nul_text"),
    pytest.param("uid=alice*)%2500", id="attr_double_encoded_nul"),
    pytest.param("*)" + ")%2500", id="bare_double_encoded_nul"),
    pytest.param("uid=alice*)%00", id="attr_percent_nul_regression"),
    pytest.param("*)" + ")%00", id="bare_percent_nul_regression"),
]


@pytest.mark.parametrize("body", LDAP_NUL_FAMILY_BODIES)
async def test_nul_family_in_body_fires_ldap(body: str) -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SecurityConfig())
    try:
        assert await _body_is_threat(body) is True
        categories = await _body_categories(body)
        assert "ldap" in categories
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config


async def test_decoded_null_byte_patterns_registered_in_url_decoded_view_only(
    manager: SusPatternsManager,
) -> None:
    assert _LDAP_NULL_BYTE_DECODED_ATTR_RE in DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES
    assert _LDAP_NULL_BYTE_DECODED_BARE_RE in DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES
    assert (
        _LDAP_NULL_BYTE_DECODED_ATTR_RE not in DETECTION_RAW_VIEW_PATTERN_SOURCES
    )
    assert (
        _LDAP_NULL_BYTE_DECODED_BARE_RE not in DETECTION_RAW_VIEW_PATTERN_SOURCES
    )
    assert _LDAP_NULL_BYTE_ATTR_RE in DETECTION_RAW_VIEW_PATTERN_SOURCES
    assert _LDAP_NULL_BYTE_BARE_RE in DETECTION_RAW_VIEW_PATTERN_SOURCES
    assert _LDAP_NULL_BYTE_ATTR_RE not in DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES
    assert _LDAP_NULL_BYTE_BARE_RE not in DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES


async def test_double_encoded_attr_nul_caught_by_decoded_view_pattern(
    manager: SusPatternsManager,
) -> None:
    result = await _manager_detect("uid=alice*)%2500", manager)
    threats = [
        threat
        for threat in result["threats"]
        if threat.get("type") == "regex"
        and threat.get("category") == "ldap"
        and threat.get("pattern") == _LDAP_NULL_BYTE_DECODED_ATTR_RE
    ]
    assert threats
    assert threats[0]["pattern"] == _LDAP_NULL_BYTE_DECODED_ATTR_RE


async def test_double_encoded_bare_nul_caught_by_decoded_view_pattern(
    manager: SusPatternsManager,
) -> None:
    result = await _manager_detect("*)" + ")%2500", manager)
    threats = [
        threat
        for threat in result["threats"]
        if threat.get("type") == "regex"
        and threat.get("category") == "ldap"
        and threat.get("pattern") == _LDAP_NULL_BYTE_DECODED_BARE_RE
    ]
    assert threats
    assert threats[0]["pattern"] == _LDAP_NULL_BYTE_DECODED_BARE_RE


LDAP_NULL_BYTE_FP_BODIES = [
    pytest.param("uid=alice)(objectClass=user)", id="benign_ldap_filter"),
    pytest.param("(uid=*)(cn=*))", id="benign_wildcard_conjunction"),
    pytest.param("report;final.pdf", id="benign_semicolon_pdf"),
    pytest.param("function foo(a)(b))", id="benign_double_close_paren"),
    pytest.param("hello" + _NUL_RAW + "world", id="raw_nul_without_filter_shape"),
]


@pytest.mark.parametrize("body", LDAP_NULL_BYTE_FP_BODIES)
async def test_benign_bodies_do_not_fire_ldap_null_byte_patterns(
    body: str, manager: SusPatternsManager
) -> None:
    result = await _manager_detect(body, manager)
    assert not _null_byte_threats(result)


async def test_raw_nul_attr_survives_signal_preserving_view(
    manager: SusPatternsManager,
) -> None:
    result = await _manager_detect("uid=alice*)" + _NUL_RAW, manager)
    threats = [
        threat
        for threat in result["threats"]
        if threat.get("type") == "regex"
        and threat.get("category") == "ldap"
        and threat.get("pattern") == _LDAP_NULL_BYTE_ATTR_RE
    ]
    assert threats
    assert threats[0]["pattern"] == _LDAP_NULL_BYTE_ATTR_RE


async def test_literal_text_nul_caught_by_raw_view_pattern(
    manager: SusPatternsManager,
) -> None:
    result = await _manager_detect("uid=alice*)" + _NUL_UNICODE_TEXT, manager)
    threats = [
        threat
        for threat in result["threats"]
        if threat.get("type") == "regex"
        and threat.get("category") == "ldap"
        and threat.get("pattern") == _LDAP_NULL_BYTE_ATTR_RE
    ]
    assert threats
    assert threats[0]["pattern"] == _LDAP_NULL_BYTE_ATTR_RE