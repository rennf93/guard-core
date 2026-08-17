from collections.abc import Generator

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.suspatterns_handler import (
    _FILE_UPLOAD_TRUNCATION_RE,
    SusPatternsManager,
)
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest


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


def _body_request(body: str) -> SyncMockGuardRequest:
    encoded = body.encode()
    return SyncMockGuardRequest(
        path="/upload",
        method="POST",
        headers={"content-length": str(len(encoded))},
        body_content=encoded,
    )


def _body_categories(body: str) -> list[str]:
    result = detect_penetration_attempt(_body_request(body), SecurityConfig())
    return list(result.threat_categories)


def _body_is_threat(body: str) -> bool:
    result = detect_penetration_attempt(_body_request(body), SecurityConfig())
    return bool(result.is_threat)


def _manager_truncation_threats(manager: SusPatternsManager, body: str) -> list[dict]:
    result = manager.detect(body, "203.0.113.9", context="request_body")
    return [
        threat
        for threat in result["threats"]
        if threat["type"] == "regex" and threat["pattern"] == _FILE_UPLOAD_TRUNCATION_RE
    ]


NUL_TRUNCATION_EVASION_BODIES = [
    pytest.param('filename="shell.php%00.txt"', id="percent_encoded_nul"),
    pytest.param('filename="shell.php\\x00.txt"', id="escaped_hex_nul_text"),
    pytest.param('filename="shell.php\\u0000.txt"', id="escaped_unicode_nul_text"),
    pytest.param('filename="shell.php\x00.txt"', id="raw_nul_byte"),
]


@pytest.mark.parametrize("body", NUL_TRUNCATION_EVASION_BODIES)
def test_nul_truncation_evasion_in_body_fires_file_upload(
    body: str,
) -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SecurityConfig())
    try:
        categories = _body_categories(body)
        assert "file_upload" in categories
        assert _body_is_threat(body) is True
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config


@pytest.mark.parametrize("body", NUL_TRUNCATION_EVASION_BODIES)
def test_nul_truncation_evasion_fires_in_enhanced_mode_via_raw_view(
    manager: SusPatternsManager, body: str
) -> None:
    result = manager.detect(body, "203.0.113.9", context="request_body")
    assert result["detection_method"] == "enhanced"
    threats = _manager_truncation_threats(manager, body)
    assert threats
    assert threats[0]["category"] == "file_upload"


def test_bare_dangerous_extension_in_body_still_fires() -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SecurityConfig())
    try:
        categories = _body_categories('filename="shell.php"')
        assert "file_upload" in categories
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config


def test_trailing_dot_truncation_in_body_still_fires() -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SecurityConfig())
    try:
        categories = _body_categories('filename="shell.php."')
        assert "file_upload" in categories
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config


def test_double_extension_in_body_still_fires() -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SecurityConfig())
    try:
        categories = _body_categories('filename="shell.php.jpg"')
        assert "file_upload" in categories
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config


def test_benign_php_txt_filename_in_body_not_flagged(
    manager: SusPatternsManager,
) -> None:
    assert _body_is_threat('filename="shell.php.txt"') is False
    result = manager.detect(
        'filename="shell.php.txt"', "203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is False


def test_benign_photo_filename_in_body_not_flagged(
    manager: SusPatternsManager,
) -> None:
    assert _body_is_threat('filename="vacation.jpg"') is False


SPACE_IN_FILENAME_BODIES = [
    pytest.param('filename="notes.php .txt"', id="notes_php_space_txt"),
    pytest.param('filename="my report.php .txt"', id="my_report_php_space_txt"),
]


@pytest.mark.parametrize("body", SPACE_IN_FILENAME_BODIES)
def test_space_in_filename_is_not_a_truncation_vector(
    body: str,
) -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SecurityConfig())
    try:
        assert _body_is_threat(body) is False
        categories = _body_categories(body)
        assert "file_upload" not in categories
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config


def test_space_bridge_is_not_a_double_extension_vector() -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SecurityConfig())
    try:
        assert _body_is_threat('filename="vacation photo.php .jpg"') is False
        categories = _body_categories('filename="vacation photo.php .jpg"')
        assert "file_upload" not in categories
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config


CONTROL_CHAR_BRIDGE_DOUBLE_EXTENSION_BODIES = [
    pytest.param('filename="shell.php\n.jpg"', id="newline_bridge"),
    pytest.param('filename="shell.php\r.jpg"', id="carriage_return_bridge"),
    pytest.param('filename="shell.php\t.jpg"', id="tab_bridge"),
]


@pytest.mark.parametrize("body", CONTROL_CHAR_BRIDGE_DOUBLE_EXTENSION_BODIES)
def test_control_char_bridge_is_a_double_extension_vector(body: str) -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SecurityConfig())
    try:
        assert _body_is_threat(body) is True
        categories = _body_categories(body)
        assert "file_upload" in categories
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config


SEMICOLON_TRUNCATION_BODIES = [
    pytest.param('filename="shell.php;x=1"', id="php_semicolon_path_info"),
    pytest.param('filename="shell.asp;.jpg"', id="asp_semicolon_path_info"),
]


@pytest.mark.parametrize("body", SEMICOLON_TRUNCATION_BODIES)
def test_semicolon_truncation_vector_still_fires(
    body: str,
) -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SecurityConfig())
    try:
        categories = _body_categories(body)
        assert "file_upload" in categories
        assert _body_is_threat(body) is True
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config


def test_double_encoded_nul_truncation_pending_url_decoded_view() -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SecurityConfig())
    try:
        assert _body_is_threat('filename="shell.php%2500.txt"') is False
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config
