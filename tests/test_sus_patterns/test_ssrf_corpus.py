import pytest

from guard_core.handlers.suspatterns_handler import sus_patterns_handler

PRIVATE_TARGET_URLS_FLAGGED = [
    pytest.param(
        "http://169.254.169.254/latest/meta-data/", id="cloud_metadata_endpoint"
    ),
    pytest.param("http://localhost:8080/admin", id="localhost_with_port"),
    pytest.param("http://192.168.1.1/admin", id="private_class_c"),
    pytest.param("http://10.0.0.1/admin", id="private_class_a"),
    pytest.param("http://172.16.0.1/admin", id="private_class_b_low"),
    pytest.param("http://172.31.255.255/admin", id="private_class_b_high"),
    pytest.param("connect to 127.0.0.1/status now", id="loopback_in_prose"),
    pytest.param("reset via 0.0.0.0:9999 first", id="unspecified_with_port"),
]

VERSION_LIKE_TEXT_NOT_FLAGGED = [
    pytest.param("software 10.4.2 release", id="three_part_version_ten"),
    pytest.param("we ship v10.14.2 today", id="three_part_version_prefixed"),
    pytest.param("the price range is $10 to $50 for the order", id="dollar_amount_ten"),
    pytest.param(
        "192.168 is a common prefix in networking docs", id="bare_two_octet_prefix"
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", PRIVATE_TARGET_URLS_FLAGGED)
async def test_private_target_url_flagged_as_ssrf(payload: str) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == "ssrf" for threat in result["threats"])


@pytest.mark.asyncio
@pytest.mark.parametrize("text", VERSION_LIKE_TEXT_NOT_FLAGGED)
async def test_version_like_text_not_flagged_as_ssrf(text: str) -> None:
    result = await sus_patterns_handler.detect(
        content=text, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False
