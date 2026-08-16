from collections.abc import Generator

import pytest

from guard_core.sync.handlers.suspatterns_handler import (
    _FILE_UPLOAD_DOUBLE_EXTENSION_RE,
    _FILE_UPLOAD_TRUNCATION_RE,
    SusPatternsManager,
)

_BYPASS_PATTERN_SOURCES = {_FILE_UPLOAD_DOUBLE_EXTENSION_RE, _FILE_UPLOAD_TRUNCATION_RE}


@pytest.fixture
def manager() -> Generator[SusPatternsManager, None, None]:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config

    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    new_instance = SusPatternsManager()

    yield new_instance

    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config


def _bypass_pattern_threats(
    manager: SusPatternsManager, payload: str, context: str = "header"
) -> list[dict]:
    result = manager.detect(payload, "127.0.0.1", context=context)
    return [
        threat
        for threat in result["threats"]
        if threat["type"] == "regex" and threat["pattern"] in _BYPASS_PATTERN_SOURCES
    ]


def _file_upload_detected(
    manager: SusPatternsManager, payload: str, context: str = "header"
) -> bool:
    result = manager.detect(payload, "127.0.0.1", context=context)
    categories = {threat["category"] for threat in result["threats"]}
    return bool(result["is_threat"]) and "file_upload" in categories


def test_double_extension_php_then_image_extension_is_detected(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="shell.php.jpg"')
    assert threats
    assert threats[0]["category"] == "file_upload"


def test_double_extension_asp_then_image_extension_is_detected(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, "filename='malware.asp.png'")
    assert threats


def test_double_extension_phtml_then_image_extension_is_detected(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="avatar.phtml.gif"')
    assert threats


def test_double_extension_aspx_is_not_swallowed_by_shorter_asp_alternative(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="shell.aspx.png"')
    assert threats


def test_double_extension_php_variant_with_digits_is_detected(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="shell.php3.jpg"')
    assert threats


def test_double_extension_pht_then_image_extension_is_detected(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="shell.pht.jpg"')
    assert threats


def test_percent_encoded_null_byte_truncation_is_detected(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="shell.php%00.jpg"')
    assert threats


def test_raw_null_byte_truncation_is_detected(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="shell.php\x00.jpg"')
    assert threats


def test_escaped_hex_null_byte_text_is_detected(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="shell.php\\x00.jpg"')
    assert threats


def test_escaped_unicode_null_byte_text_is_detected(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="shell.php\\u0000.jpg"')
    assert threats


def test_short_escaped_null_byte_text_is_detected(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="shell.php\\0.jpg"')
    assert threats


def test_trailing_dot_after_dangerous_extension_is_detected(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="shell.php."')
    assert threats


def test_trailing_space_after_dangerous_extension_is_detected(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="shell.php "')
    assert threats


def test_semicolon_path_info_trick_is_detected(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="shell.asp;.jpg"')
    assert threats


def test_php_semicolon_path_info_trick_is_detected(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="shell.php;.jpg"')
    assert threats


def test_short_asp_double_extension_is_detected(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="x.asp.png"')
    assert threats


def test_semicolon_without_second_extension_is_detected(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="shell.cmd;"')
    assert threats


def test_uppercase_double_extension_is_detected(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="SHELL.PHP.JPG"')
    assert threats


def test_uppercase_hex_null_byte_escape_is_detected(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="shell.php\\X00.jpg"')
    assert threats


def test_detected_threat_matches_a_bypass_pattern_source(
    manager: SusPatternsManager,
) -> None:
    result = manager.detect('filename="shell.php.jpg"', "127.0.0.1", context="header")
    assert result["is_threat"] is True
    matched_sources = {
        threat["pattern"] for threat in result["threats"] if threat["type"] == "regex"
    }
    assert matched_sources & _BYPASS_PATTERN_SOURCES


def test_single_dangerous_extension_without_trailing_content_is_not_bypass(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="shell.php"')
    assert threats == []


def test_extension_glued_to_more_letters_is_not_flagged(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="phpmyadmin_backup.jpg"')
    assert threats == []


def test_benign_multi_dot_archive_filename_is_not_flagged(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="archive.tar.gz"')
    assert threats == []


def test_benign_multi_dot_notes_filename_is_not_flagged(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="my.notes.txt"')
    assert threats == []


def test_benign_versioned_filename_is_not_flagged(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="report.v2.final.pdf"')
    assert threats == []


def test_benign_shell_script_tar_gz_backup_is_not_flagged(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="backup.sh.tar.gz"')
    assert threats == []


def test_benign_war_gz_backup_is_not_flagged(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="myapp.war.gz"')
    assert threats == []


def test_benign_python_zip_backup_is_not_flagged(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="data.py.zip"')
    assert threats == []


def test_benign_shell_script_gz_backup_is_not_flagged(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="install.sh.gz"')
    assert threats == []


def test_domain_like_dot_com_in_middle_of_filename_is_not_flagged(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="backup.example.com.pdf"')
    assert threats == []


def test_benign_single_extension_filename_is_not_flagged(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="avatar.png"')
    assert threats == []


def test_benign_sourcemap_double_extension_is_not_flagged(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="data.min.js.map"')
    assert threats == []


def test_benign_python_source_txt_extension_is_not_flagged(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="script.py.txt"')
    assert threats == []


def test_benign_exe_backup_extension_is_not_flagged(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="log.exe.bak"')
    assert threats == []


def test_benign_disabled_asp_extension_is_not_flagged(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="page.asp.orig"')
    assert threats == []


def test_benign_dated_invoice_filename_is_not_flagged(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="invoice.2024.pdf"')
    assert threats == []


def test_pht_extension_is_detected(manager: SusPatternsManager) -> None:
    assert _file_upload_detected(manager, 'filename="shell.pht"')


def test_jspx_extension_is_detected(manager: SusPatternsManager) -> None:
    assert _file_upload_detected(manager, 'filename="shell.jspx"')


def test_shtml_extension_is_detected(manager: SusPatternsManager) -> None:
    assert _file_upload_detected(manager, 'filename="shell.shtml"')


def test_ashx_extension_is_detected(manager: SusPatternsManager) -> None:
    assert _file_upload_detected(manager, 'filename="shell.ashx"')


def test_asa_extension_is_detected(manager: SusPatternsManager) -> None:
    assert _file_upload_detected(manager, 'filename="shell.asa"')


def test_asax_extension_is_detected(manager: SusPatternsManager) -> None:
    assert _file_upload_detected(manager, 'filename="shell.asax"')


def test_ascx_extension_is_detected(manager: SusPatternsManager) -> None:
    assert _file_upload_detected(manager, 'filename="shell.ascx"')


def test_cfm_extension_is_detected(manager: SusPatternsManager) -> None:
    assert _file_upload_detected(manager, 'filename="shell.cfm"')


def test_cfc_extension_is_detected(manager: SusPatternsManager) -> None:
    assert _file_upload_detected(manager, 'filename="shell.cfc"')


def test_war_extension_is_detected(manager: SusPatternsManager) -> None:
    assert _file_upload_detected(manager, 'filename="shell.war"')


def test_asmx_extension_is_detected(manager: SusPatternsManager) -> None:
    assert _file_upload_detected(manager, 'filename="shell.asmx"')


def test_asmx_double_extension_is_detected(
    manager: SusPatternsManager,
) -> None:
    threats = _bypass_pattern_threats(manager, 'filename="shell.asmx.jpg"')
    assert threats


def test_cer_extension_is_detected(manager: SusPatternsManager) -> None:
    assert _file_upload_detected(manager, 'filename="shell.cer"')


def test_phps_extension_is_detected(manager: SusPatternsManager) -> None:
    assert _file_upload_detected(manager, 'filename="shell.phps"')
