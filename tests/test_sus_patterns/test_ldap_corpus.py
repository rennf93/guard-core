import pytest

from guard_core.handlers.suspatterns_handler import sus_patterns_handler

LDAP_PAREN_CONJUNCTION_STILL_FLAGGED = [
    pytest.param("(|(uid=*)(cn=*))", id="or_filter_wildcard_uid_cn"),
    pytest.param("(&(objectClass=user)(uid=*))", id="and_filter_wildcard_uid"),
    pytest.param("admin)(|(password=*", id="bare_or_paren_password_bypass"),
    pytest.param("(|(&", id="nested_filter_bypass_truncated"),
]

LDAP_PAREN_CONJUNCTION_WITHOUT_FOLLOWUP_NOT_FLAGGED = [
    pytest.param("(| end of message", id="or_paren_followed_by_prose"),
    pytest.param("(& end of message", id="and_paren_followed_by_prose"),
    pytest.param("logic gate (| means OR in this DSL", id="prose_mentions_or_paren"),
]

LDAP_WILDCARD_EQUALS_STILL_FLAGGED = [
    pytest.param("*uid=admin", id="wildcard_glued_uid_equals"),
    pytest.param("*cn=admin", id="wildcard_glued_cn_equals"),
]

LDAP_WILDCARD_EQUALS_UNBOUNDED_NOISE_NOT_FLAGGED = [
    pytest.param("*" + ("x" * 200) + "=end", id="wildcard_then_long_word_run_equals"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", LDAP_PAREN_CONJUNCTION_STILL_FLAGGED)
async def test_ldap_paren_conjunction_still_flagged(payload: str) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == "ldap" for threat in result["threats"])


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", LDAP_PAREN_CONJUNCTION_WITHOUT_FOLLOWUP_NOT_FLAGGED)
async def test_ldap_paren_conjunction_without_followup_not_flagged(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert not any(threat.get("category") == "ldap" for threat in result["threats"])


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", LDAP_WILDCARD_EQUALS_STILL_FLAGGED)
async def test_ldap_wildcard_equals_still_flagged(payload: str) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == "ldap" for threat in result["threats"])


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", LDAP_WILDCARD_EQUALS_UNBOUNDED_NOISE_NOT_FLAGGED)
async def test_ldap_wildcard_equals_unbounded_noise_not_flagged(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert not any(threat.get("category") == "ldap" for threat in result["threats"])
