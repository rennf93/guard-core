import pytest

from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager


def _build_isolated_manager() -> SusPatternsManager:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    manager = SusPatternsManager()
    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config
    return manager


_MANAGER = _build_isolated_manager()


def _detected_categories(content: str) -> set[str]:
    result = _MANAGER.detect(content, "203.0.113.9", "request_body")
    if not result["is_threat"]:
        return set()
    return {threat.get("category") for threat in result["threats"]}


@pytest.mark.parametrize(
    ("case_id", "category", "payload"),
    [
        (
            "cmd_injection_embedded_after_newline",
            "cmd_injection",
            "some description field\nbash -c 'rm -rf /'",
        ),
        (
            "sqli_embedded_hash_comment_before_more_content",
            "sqli",
            "comment='malicious'#\nrest of json continues after",
        ),
        (
            "sqli_embedded_order_by_before_header_line",
            "sqli",
            "sort=ORDER BY 1\nX-Extra-Header: value",
        ),
        (
            "cms_probing_standalone_control",
            "cms_probing",
            "/wp-admin/setup-config.php",
        ),
    ],
)
def test_attack_embedded_in_larger_body_is_detected(
    case_id: str, category: str, payload: str
) -> None:
    assert category in _detected_categories(payload), case_id


@pytest.mark.parametrize(
    ("case_id", "payload"),
    [
        (
            "cms_probing_scheme_embedded_url_in_redirect_sentence",
            "Redirecting to http://example.com/wp-admin/setup-config.php now",
        ),
        (
            "cms_probing_scheme_embedded_url_in_support_ticket",
            "Customer sent us this link: "
            "https://shop.example.com/wp-admin/plugins.php please advise.",
        ),
        (
            "cms_probing_scheme_embedded_url_in_docs_note",
            "See notes at https://docs.example.com/wp-admin/setup-config.php "
            "for migration steps.",
        ),
    ],
)
def test_cms_probing_scheme_embedded_url_in_prose_stays_unflagged(
    case_id: str, payload: str
) -> None:
    assert "cms_probing" not in _detected_categories(payload), case_id


@pytest.mark.parametrize(
    ("case_id", "payload"),
    [
        (
            "git_diff_ending_in_python_source_path",
            "diff --git a/src/utils.py b/src/utils.py\n--- a/src/utils.py\n"
            "+++ b/src/utils.py",
        ),
        (
            "doc_last_line_ends_in_readme_txt_path",
            "Legacy download docs:\n"
            "Older clients should use ftp://ftp.example.com/pub/readme.txt",
        ),
        (
            "incident_note_mentions_etc_passwd_mid_message",
            "Investigating auth issues.\n"
            "User confirmed the target file was /etc/passwd\n"
            "Ticket resolved, closing now.",
        ),
        (
            "bullet_list_wp_admin_alone_on_line",
            "Available admin paths historically used:\nwp-admin\n"
            "Remove legacy references.",
        ),
        (
            "bullet_list_htaccess_alone_on_line",
            "Files reviewed during the audit:\n.htaccess\nNo secrets found.",
        ),
    ],
)
def test_benign_multiline_document_stays_unflagged(case_id: str, payload: str) -> None:
    assert _detected_categories(payload) == set(), case_id


@pytest.mark.parametrize(
    ("case_id", "payload"),
    [
        (
            "gcp_computeMetadata_default_service_account_segment",
            "computeMetadata/v1/instance/service-accounts/default/token",
        ),
        ("bare_aws_credentials_file_path", "~/.aws/credentials"),
        ("kubernetes_default_namespace_pods_path", "/api/v1/namespaces/default/pods"),
        ("kubernetes_default_namespace_bare_path", "/api/v1/namespaces/default"),
    ],
)
def test_recon_path_segment_amid_unrelated_path_stays_unflagged(
    case_id: str, payload: str
) -> None:
    detected = _detected_categories(payload)
    assert "recon" not in detected, case_id


@pytest.mark.parametrize(
    "payload",
    [
        "/default.asp",
        "/default/",
        "/inicio.html",
        "/localstart.asp",
        "/management",
        "/credentials",
        "/config_dump",
    ],
)
def test_recon_legacy_default_and_management_probes_still_detected(
    payload: str,
) -> None:
    assert "recon" in _detected_categories(payload)


@pytest.mark.parametrize(
    "payload",
    [
        "/api/version",
        "/app/system/health",
        "/api/v2/system/status",
    ],
)
def test_recon_bare_rest_convention_routes_stay_unflagged(
    payload: str,
) -> None:
    assert "recon" not in _detected_categories(payload)


def test_recon_system_and_version_paired_probe_still_detected() -> None:
    assert "recon" in _detected_categories("/v2/system/version")


@pytest.mark.parametrize(
    ("case_id", "payload"),
    [
        ("cms_probing_nested_wp_content_themes_default", "/wp-content/themes/default"),
        ("recon_nested_inicio_html", "/en/inicio.html"),
    ],
)
def test_recon_nested_default_style_probes_are_detected(
    case_id: str, payload: str
) -> None:
    detected = _detected_categories(payload)
    assert detected & {"recon", "cms_probing"}, case_id


@pytest.mark.parametrize(
    "payload",
    [
        "cn=*)(uid=*",
        "*)(password=*)",
        "*)((objectClass=*",
        "*))%00",
    ],
)
def test_ldap_wildcard_bypass_without_leading_conjunction_is_detected(
    payload: str,
) -> None:
    assert "ldap" in _detected_categories(payload)


def test_ldap_wildcard_and_parens_in_benign_prose_stays_unflagged() -> None:
    payload = "glob pattern *.log matches all logs (see docs)"
    assert "ldap" not in _detected_categories(payload)


@pytest.mark.parametrize(
    "payload",
    [
        "/bin/sh -c id",
        "env bash -c id",
    ],
)
def test_cmd_injection_absolute_path_or_env_prefixed_shell_is_detected(
    payload: str,
) -> None:
    assert "cmd_injection" in _detected_categories(payload)


def test_cmd_injection_shell_path_mention_without_flag_stays_unflagged() -> None:
    payload = "The path /bin/sh is the default shell on many systems."
    assert "cmd_injection" not in _detected_categories(payload)


@pytest.mark.parametrize(
    "payload",
    [
        "/usr/bin/env bash -c id",
        "; /usr/bin/env sh -c id",
    ],
)
def test_cmd_injection_path_prefixed_env_shell_is_detected(
    payload: str,
) -> None:
    assert "cmd_injection" in _detected_categories(payload)


@pytest.mark.parametrize(
    "payload",
    [
        "; ./deploy.sh -f",
        "scripts/run.sh -v",
        "Run ./scripts/lint.sh -v before pushing.",
    ],
)
def test_cmd_injection_script_name_ending_in_shell_stays_unflagged(
    payload: str,
) -> None:
    assert "cmd_injection" not in _detected_categories(payload)
