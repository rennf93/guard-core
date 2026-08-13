import pytest

from guard_core.handlers.suspatterns_handler import SusPatternsManager


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


async def _detected_categories(content: str) -> set[str]:
    result = await _MANAGER.detect(content, "203.0.113.9", "request_body")
    if not result["is_threat"]:
        return set()
    return {threat.get("category") for threat in result["threats"]}


@pytest.mark.asyncio
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
async def test_attack_embedded_in_larger_body_is_detected(
    case_id: str, category: str, payload: str
) -> None:
    assert category in await _detected_categories(payload), case_id


@pytest.mark.asyncio
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
async def test_cms_probing_scheme_embedded_url_in_prose_stays_unflagged(
    case_id: str, payload: str
) -> None:
    assert "cms_probing" not in await _detected_categories(payload), case_id


@pytest.mark.asyncio
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
async def test_benign_multiline_document_stays_unflagged(
    case_id: str, payload: str
) -> None:
    assert await _detected_categories(payload) == set(), case_id


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case_id", "payload"),
    [
        (
            "gcp_computeMetadata_default_service_account_segment",
            "computeMetadata/v1/instance/service-accounts/default/token",
        ),
        ("bare_aws_credentials_file_path", "~/.aws/credentials"),
        ("kubernetes_default_namespace_pods_path", "/api/v1/namespaces/default/pods"),
    ],
)
async def test_recon_path_segment_amid_unrelated_path_stays_unflagged(
    case_id: str, payload: str
) -> None:
    detected = await _detected_categories(payload)
    assert "recon" not in detected, case_id


@pytest.mark.asyncio
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
async def test_recon_legacy_default_and_management_probes_still_detected(
    payload: str,
) -> None:
    assert "recon" in await _detected_categories(payload)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        "/api/version",
        "/app/system/health",
        "/api/v2/system/status",
    ],
)
async def test_recon_bare_rest_convention_routes_stay_unflagged(
    payload: str,
) -> None:
    assert "recon" not in await _detected_categories(payload)


async def test_recon_system_and_version_paired_probe_still_detected() -> None:
    assert "recon" in await _detected_categories("/v2/system/version")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        "cn=*)(uid=*",
        "*)(password=*)",
    ],
)
async def test_ldap_wildcard_bypass_without_leading_conjunction_is_detected(
    payload: str,
) -> None:
    assert "ldap" in await _detected_categories(payload)


async def test_ldap_wildcard_and_parens_in_benign_prose_stays_unflagged() -> None:
    payload = "glob pattern *.log matches all logs (see docs)"
    assert "ldap" not in await _detected_categories(payload)
