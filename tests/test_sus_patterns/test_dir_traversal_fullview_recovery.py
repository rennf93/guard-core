import pytest

from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

_CONFIG = SecurityConfig()


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


def _text_body_request(body: str) -> MockGuardRequest:
    encoded = body.encode()
    headers = {
        "content-length": str(len(encoded)),
        "content-type": "text/plain",
    }
    return MockGuardRequest(body_content=encoded, headers=headers)


async def _assert_body_fires_dir_traversal(body: str) -> None:
    request = _text_body_request(body)
    result = await detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.threat_categories == ["dir_traversal"]


async def _assert_body_does_not_fire(body: str) -> None:
    request = _text_body_request(body)
    result = await detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is False


@pytest.mark.asyncio
async def test_etc_passwd_url_encoded_body_fires_dir_traversal() -> None:
    await _assert_body_fires_dir_traversal("%2fetc%2fpasswd")


@pytest.mark.asyncio
async def test_windows_ini_url_encoded_body_fires_dir_traversal() -> None:
    await _assert_body_fires_dir_traversal("%2fboot.ini")


@pytest.mark.asyncio
async def test_proc_environ_url_encoded_body_fires_dir_traversal() -> None:
    await _assert_body_fires_dir_traversal("%2fproc%2fself%2fenviron")


@pytest.mark.asyncio
async def test_var_log_url_encoded_body_fires_dir_traversal() -> None:
    await _assert_body_fires_dir_traversal("%2fvar%2flog%2fauth.log")


@pytest.mark.asyncio
async def test_etc_passwd_single_line_body_still_fires() -> None:
    await _assert_body_fires_dir_traversal("/etc/passwd")


@pytest.mark.asyncio
async def test_etc_passwd_inline_single_line_body_still_fires() -> None:
    await _assert_body_fires_dir_traversal("foo=bar /etc/passwd")


@pytest.mark.asyncio
async def test_windows_ini_single_line_body_still_fires() -> None:
    await _assert_body_fires_dir_traversal("boot.ini")


@pytest.mark.asyncio
async def test_proc_environ_single_line_body_still_fires() -> None:
    await _assert_body_fires_dir_traversal("proc/self/environ")


@pytest.mark.asyncio
async def test_var_log_single_line_body_still_fires() -> None:
    await _assert_body_fires_dir_traversal("var/log/auth.log")


@pytest.mark.asyncio
async def test_etc_passwd_multiline_body_not_detected() -> None:
    await _assert_body_does_not_fire("foo=bar\n/etc/passwd")


@pytest.mark.asyncio
async def test_windows_ini_multiline_body_not_detected() -> None:
    await _assert_body_does_not_fire("foo=bar\nboot.ini")


@pytest.mark.asyncio
async def test_proc_environ_multiline_body_not_detected() -> None:
    await _assert_body_does_not_fire("foo=bar\nproc/self/environ")


@pytest.mark.asyncio
async def test_var_log_multiline_body_not_detected() -> None:
    await _assert_body_does_not_fire("foo=bar\nvar/log/auth.log")


@pytest.mark.asyncio
async def test_etc_passwd_incident_note_prose_not_detected() -> None:
    await _assert_body_does_not_fire(
        "Incident note: server rebooted at 03:00.\n"
        "Verified /etc/passwd had no unauthorized accounts"
    )


@pytest.mark.asyncio
async def test_windows_ini_setup_log_prose_not_detected() -> None:
    await _assert_body_does_not_fire(
        "Setup log step 3 complete.\nRead boot.ini to confirm boot loader options"
    )


@pytest.mark.asyncio
async def test_proc_environ_debug_trace_prose_not_detected() -> None:
    await _assert_body_does_not_fire(
        "Debug trace captured connection handshake.\n"
        "Inspecting proc/self/environ for env var leakage check"
    )


@pytest.mark.asyncio
async def test_var_log_ops_report_prose_not_detected() -> None:
    await _assert_body_does_not_fire(
        "Ops report for nightly maintenance window.\n"
        "Reviewed var/log/auth.log for ssh failures"
    )


@pytest.mark.asyncio
async def test_benign_body_not_detected() -> None:
    await _assert_body_does_not_fire("hello world")


@pytest.mark.asyncio
async def test_enhanced_mode_is_active_for_dir_traversal_bodies() -> None:
    result = await sus_patterns_handler.detect(
        content="%2fetc%2fpasswd",
        ip_address="203.0.113.9",
        context="request_body",
    )
    assert result["detection_method"] == "enhanced"
    assert result["is_threat"] is True
