import pytest

from guard_core.handlers.suspatterns_handler import sus_patterns_handler

ORDINARY_URLS_NOT_FLAGGED = [
    pytest.param("https://example.com", id="bare_https"),
    pytest.param("http://example.com", id="bare_http"),
    pytest.param("ftp://ftp.example.com/pub/file.txt", id="bare_ftp"),
    pytest.param(
        '{"callback_url": "https://api.customer.com/webhook"}',
        id="json_webhook_url",
    ),
    pytest.param('{"profile": "https://example.com/u/123"}', id="json_profile_link"),
    pytest.param(
        "see https://example.com/docs for more information", id="prose_docs_link"
    ),
    pytest.param(
        "see https://github.com/rennf93/guard-core for the source",
        id="prose_github_link",
    ),
    pytest.param("https://example.com/search?q=hello&page=2", id="query_string_basic"),
    pytest.param(
        "https://example.com/callback?redirect=%2Fhome", id="query_string_encoded"
    ),
    pytest.param("https://example.com:8443/path", id="port_https"),
    pytest.param("http://api.example.com:8080/status", id="port_http_public_host"),
    pytest.param("https://user:pass@example.com/path", id="auth_userinfo"),
    pytest.param("https://api:token123@service.example.com/v1", id="auth_token"),
    pytest.param("https://xn--80akhbyknj4f.example/", id="idn_punycode_domain"),
    pytest.param("https://münchen.example/", id="idn_unicode_domain"),
    pytest.param("https://[2001:db8::1]/path", id="ipv6_literal"),
    pytest.param("https://[2001:db8::1]:8443/api", id="ipv6_literal_with_port"),
]

PROTOCOL_RELATIVE_RFI_STILL_FLAGGED = [
    pytest.param("//evil.com/shell.txt", id="protocol_relative_bare"),
    pytest.param("?file=//evil.com/x.txt", id="protocol_relative_file_param"),
    pytest.param("?page=//attacker.net/payload", id="protocol_relative_page_param"),
    pytest.param("src=//evil.io/malicious.js", id="protocol_relative_src_attr"),
    pytest.param(
        "redirect=//phishing.example/login", id="protocol_relative_redirect_param"
    ),
]

BARE_DOUBLE_SLASH_WITHOUT_HOST_SHAPE_NOT_FLAGGED = [
    pytest.param("//abc", id="bare_single_label_no_dot"),
    pytest.param("//shellcode", id="bare_word_no_dot"),
    pytest.param("path=//internalservice", id="param_single_label_no_dot"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", ORDINARY_URLS_NOT_FLAGGED)
async def test_ordinary_url_not_flagged_as_file_inclusion(payload: str) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", PROTOCOL_RELATIVE_RFI_STILL_FLAGGED)
async def test_protocol_relative_url_still_flagged_as_file_inclusion(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "file_inclusion" for threat in result["threats"]
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", BARE_DOUBLE_SLASH_WITHOUT_HOST_SHAPE_NOT_FLAGGED)
async def test_bare_double_slash_without_host_shape_not_flagged(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is False
