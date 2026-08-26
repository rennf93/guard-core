import re
import time

import pytest

from guard_core.sync.detection_engine import PatternCompiler
from guard_core.sync.handlers.suspatterns_handler import (
    _LEGACY_DETECTION_STATE,
    _LEGACY_IPV4_HOST_RE,
    _decode_legacy_ipv4_host,
    _decode_legacy_ipv4_part,
    _is_bare_decimal_legacy_ipv4_part,
    sus_patterns_handler,
)

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
    pytest.param("http://[::ffff:127.0.0.1]/", id="ipv4_mapped_ipv6_loopback_bracket"),
    pytest.param("http://localhost./", id="localhost_trailing_dot"),
]

VERSION_LIKE_TEXT_NOT_FLAGGED = [
    pytest.param("software 10.4.2 release", id="three_part_version_ten"),
    pytest.param("we ship v10.14.2 today", id="three_part_version_prefixed"),
    pytest.param("the price range is $10 to $50 for the order", id="dollar_amount_ten"),
    pytest.param(
        "192.168 is a common prefix in networking docs", id="bare_two_octet_prefix"
    ),
]

SCHEME_PORT_NOT_FLAGGED = [
    pytest.param("redis://6379", id="redis_bare_port"),
    pytest.param("grpc://50051", id="grpc_bare_port"),
    pytest.param("amqp://5672", id="amqp_bare_port"),
    pytest.param("https://2023/blog", id="https_bare_digits_path"),
    pytest.param(
        "connect via tcp://8080 for the health probe", id="tcp_bare_port_prose"
    ),
]

KNOWN_GOOD_SSRF_TARGETS = [
    pytest.param("169.254.169.254", id="known_good_aws_metadata_ip"),
    pytest.param("localhost:8080", id="known_good_localhost_port"),
    pytest.param("127.0.0.1", id="known_good_loopback"),
    pytest.param("10.0.0.5", id="known_good_private_class_a"),
    pytest.param("192.168.1.1", id="known_good_private_class_c"),
    pytest.param("[::1]", id="known_good_ipv6_loopback"),
    pytest.param("169.254.170.2", id="known_good_ecs_metadata_ip"),
]

KNOWN_GOOD_BENIGN_TARGETS = [
    pytest.param("https://api.stripe.com/v1/charges", id="known_good_benign_stripe"),
    pytest.param("https://github.com/anthropics/claude", id="known_good_benign_github"),
    pytest.param("https://example.com/path?a=1", id="known_good_benign_example"),
    pytest.param("https://cdn.jsdelivr.net/npm/x.js", id="known_good_benign_jsdelivr"),
    pytest.param("https://s3.amazonaws.com/bucket/key.json", id="known_good_benign_s3"),
    pytest.param(
        "http://external-api.io/v2/users", id="known_good_benign_external_api"
    ),
]

ALTERNATE_ENCODED_LOOPBACK_AND_PRIVATE_IPS_FLAGGED = [
    pytest.param("http://2130706433/", id="decimal_loopback"),
    pytest.param("http://0177.0.0.1/", id="octal_loopback"),
    pytest.param("http://0x7f.1/", id="hex_mixed_loopback"),
    pytest.param("http://0x7f000001/", id="hex_single_int_loopback"),
    pytest.param("http://017700000001/", id="octal_single_int_loopback"),
    pytest.param("http://0x7f.0.0.1/", id="hex_dotted_full_loopback"),
    pytest.param("http://127.0.0.0x1/", id="mixed_last_octet_hex_loopback"),
    pytest.param("http://0xA.0.0.5/", id="hex_first_octet_private_10"),
    pytest.param("http://0x0A000005/", id="hex_single_int_private_10"),
    pytest.param("http://167772165/", id="decimal_private_10"),
    pytest.param("http://012.0.0.5/", id="octal_first_octet_private_10"),
    pytest.param("http://0xC0.0xA8.1.1/", id="hex_dotted_private_192_168"),
    pytest.param("http://3232235777/", id="decimal_private_192_168"),
    pytest.param("http://0254.020.0.1/", id="octal_dotted_172_private"),
    pytest.param("http://0xAC.16.0.1/", id="hex_decimal_mixed_172_private"),
    pytest.param("http://0251.0376.1.1/", id="octal_dotted_169_254"),
    pytest.param("http://0xA9FEA9FE/", id="hex_single_int_169_254"),
    pytest.param("http://0000000000/", id="decimal_zero_unspecified"),
    pytest.param(
        "http://user@2130706433:8080/x", id="decimal_loopback_with_userinfo_and_port"
    ),
]

CLOUD_METADATA_TARGETS_FLAGGED = [
    pytest.param(
        "http://metadata.google.internal/latest/",
        id="gcp_metadata_internal",
    ),
    pytest.param("http://metadata.goog/latest/", id="gcp_metadata_goog"),
    pytest.param("http://100.100.100.200/latest/meta-data/", id="alibaba_metadata"),
]

PUBLIC_ADDRESSES_NOT_FLAGGED = [
    pytest.param("http://8.8.8.8/", id="public_dns_google"),
    pytest.param("http://134744072/", id="decimal_encoded_public_dns"),
    pytest.param("http://1.1.1.1/", id="public_dns_cloudflare"),
    pytest.param("http://93.184.216.34/", id="public_example_com_ip"),
    pytest.param("localhost.example.com/callback", id="localhost_lookalike_domain"),
    pytest.param("http://999.999.999.999/", id="malformed_octets_out_of_range"),
    pytest.param("http://08.0.0.1/", id="invalid_octal_digit_rejected"),
    pytest.param("http://[::ffff:8.8.8.8]/", id="ipv4_mapped_ipv6_public_bracket"),
    pytest.param("http://0x.0.0.1/", id="empty_hex_digits_rejected"),
]

BENIGN_URL_CORPUS_NOT_FLAGGED = [
    pytest.param("https://api.stripe.com/v1/charges", id="stripe_api"),
    pytest.param("https://github.com/anthropics/claude", id="github"),
    pytest.param("https://example.com/path?a=1", id="example_query"),
    pytest.param("https://cdn.jsdelivr.net/npm/x.js", id="jsdelivr_cdn"),
    pytest.param("https://s3.amazonaws.com/bucket/key.json", id="s3_bucket"),
    pytest.param("http://external-api.io/v2/users", id="external_api"),
    pytest.param(
        "https://unpkg.com/react@18/umd/react.production.min.js", id="unpkg_cdn"
    ),
    pytest.param(
        "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js",
        id="cdnjs_cloudflare",
    ),
    pytest.param("https://fonts.googleapis.com/css2?family=Roboto", id="google_fonts"),
    pytest.param("https://storage.googleapis.com/my-bucket/file.png", id="gcs_bucket"),
    pytest.param("https://my-bucket.s3.amazonaws.com/key.json", id="s3_virtual_hosted"),
    pytest.param(
        "https://my-bucket.s3.eu-west-1.amazonaws.com/key.json", id="s3_regional"
    ),
    pytest.param("https://api.github.com/repos/owner/repo/issues", id="github_api"),
    pytest.param("https://api.twilio.com/2010-04-01/Accounts", id="twilio_api"),
    pytest.param("https://hooks.slack.com/services/T000/B000/XXXX", id="slack_webhook"),
    pytest.param("https://outlook.office.com/webhook/abc123", id="outlook_webhook"),
    pytest.param("https://api.mailgun.net/v3/domain/messages", id="mailgun_api"),
    pytest.param("https://oauth2.googleapis.com/token", id="google_oauth_token"),
    pytest.param(
        "https://accounts.google.com/o/oauth2/v2/auth", id="google_oauth_authorize"
    ),
    pytest.param(
        "https://login.microsoftonline.com/common/oauth2/authorize",
        id="microsoft_oauth",
    ),
    pytest.param("https://auth0.com/authorize?client_id=abc", id="auth0_authorize"),
    pytest.param("https://api.paypal.com/v2/checkout/orders", id="paypal_api"),
    pytest.param("https://api.twitter.com/2/tweets", id="twitter_api"),
    pytest.param("https://graph.facebook.com/v15.0/me", id="facebook_graph_api"),
    pytest.param("https://api.linkedin.com/v2/me", id="linkedin_api"),
    pytest.param(
        "https://gateway.example-api.com/v1/resource", id="generic_api_gateway"
    ),
    pytest.param(
        "https://apigateway.us-east-1.amazonaws.com/prod/resource",
        id="aws_apigateway",
    ),
    pytest.param(
        "https://myapp.execute-api.us-east-1.amazonaws.com/prod/",
        id="aws_execute_api",
    ),
    pytest.param("https://webhook.site/abc-def-123", id="webhook_site"),
    pytest.param("https://requestbin.com/r/abc123", id="requestbin"),
    pytest.param("https://sentry.io/api/0/projects/", id="sentry_api"),
    pytest.param("https://api.datadoghq.com/api/v1/series", id="datadog_api"),
    pytest.param("https://api.segment.io/v1/track", id="segment_api"),
    pytest.param("https://api.mixpanel.com/track", id="mixpanel_api"),
    pytest.param(
        "https://region1.google-analytics.com/g/collect", id="google_analytics"
    ),
    pytest.param("https://api.openai.com/v1/chat/completions", id="openai_api"),
    pytest.param("https://api.anthropic.com/v1/messages", id="anthropic_api"),
    pytest.param(
        "https://raw.githubusercontent.com/owner/repo/main/file.txt",
        id="github_raw_content",
    ),
    pytest.param("https://registry.npmjs.org/react", id="npm_registry"),
    pytest.param("https://pypi.org/simple/requests/", id="pypi_simple"),
    pytest.param("localhost.example.com/callback", id="localhost_lookalike"),
    pytest.param("https://notlocalhost.io/status", id="notlocalhost_domain"),
    pytest.param("https://my-127-0-0-1.example.com/", id="loopback_lookalike_domain"),
    pytest.param("https://192-168-1-1.nip.io/", id="private_ip_lookalike_domain"),
    pytest.param(
        "https://internal-api.company-10.com/status", id="company_ten_lookalike"
    ),
]


@pytest.mark.parametrize("payload", PRIVATE_TARGET_URLS_FLAGGED)
def test_private_target_url_flagged_as_ssrf(payload: str) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == "ssrf" for threat in result["threats"])


@pytest.mark.parametrize("text", VERSION_LIKE_TEXT_NOT_FLAGGED)
def test_version_like_text_not_flagged_as_ssrf(text: str) -> None:
    result = sus_patterns_handler.detect(
        content=text, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False


@pytest.mark.parametrize("text", SCHEME_PORT_NOT_FLAGGED)
def test_scheme_with_bare_port_number_not_flagged_as_ssrf(text: str) -> None:
    result = sus_patterns_handler.detect(
        content=text, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False


@pytest.mark.parametrize("payload", KNOWN_GOOD_SSRF_TARGETS)
def test_known_good_ssrf_targets_still_detected(payload: str) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == "ssrf" for threat in result["threats"])


@pytest.mark.parametrize("payload", KNOWN_GOOD_BENIGN_TARGETS)
def test_known_good_benign_targets_stay_unflagged(payload: str) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False


@pytest.mark.parametrize("payload", ALTERNATE_ENCODED_LOOPBACK_AND_PRIVATE_IPS_FLAGGED)
def test_alternate_encoded_loopback_and_private_ip_flagged_as_ssrf(
    payload: str,
) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == "ssrf" for threat in result["threats"])


@pytest.mark.parametrize("payload", CLOUD_METADATA_TARGETS_FLAGGED)
def test_cloud_metadata_hostname_and_ip_flagged_as_ssrf(payload: str) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == "ssrf" for threat in result["threats"])


@pytest.mark.parametrize("payload", PUBLIC_ADDRESSES_NOT_FLAGGED)
def test_public_and_malformed_addresses_not_flagged_as_ssrf(
    payload: str,
) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False


@pytest.mark.parametrize("payload", BENIGN_URL_CORPUS_NOT_FLAGGED)
def test_benign_url_corpus_not_flagged_as_ssrf(payload: str) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False


def test_decode_legacy_ipv4_host_rejects_more_than_four_parts() -> None:
    assert _decode_legacy_ipv4_host("1.2.3.4.5") is None


def test_decode_legacy_ipv4_host_rejects_zero_parts() -> None:
    assert _decode_legacy_ipv4_host("") is None


def test_decode_legacy_ipv4_host_rejects_invalid_part() -> None:
    assert _decode_legacy_ipv4_host("abc.1.2.3") is None


def test_decode_legacy_ipv4_part_rejects_empty_hex_digits() -> None:
    assert _decode_legacy_ipv4_part("0x") is None


def test_decode_legacy_ipv4_part_rejects_invalid_octal_digit() -> None:
    assert _decode_legacy_ipv4_part("08") is None


def test_decode_legacy_ipv4_part_decodes_bare_zero() -> None:
    assert _decode_legacy_ipv4_part("0") == 0


def test_decode_legacy_ipv4_host_rejects_last_part_exceeding_remaining_bits() -> None:
    assert _decode_legacy_ipv4_host("1.2.3.999") is None


def test_decode_legacy_ipv4_host_rejects_bare_small_decimal() -> None:
    assert _decode_legacy_ipv4_host("6379") is None


def test_decode_legacy_ipv4_host_accepts_bare_large_decimal() -> None:
    assert _decode_legacy_ipv4_host("2130706433") == 2130706433


def test_decode_legacy_ipv4_host_accepts_bare_small_octal_zero() -> None:
    assert _decode_legacy_ipv4_host("0000000000") == 0


def test_decode_legacy_ipv4_host_accepts_bare_small_hex() -> None:
    assert _decode_legacy_ipv4_host("0x1") == 1


def test_is_bare_decimal_legacy_ipv4_part_accepts_literal_zero() -> None:
    assert _is_bare_decimal_legacy_ipv4_part("0") is True


def test_is_bare_decimal_legacy_ipv4_part_accepts_nonzero_leading_digit() -> None:
    assert _is_bare_decimal_legacy_ipv4_part("6379") is True


def test_is_bare_decimal_legacy_ipv4_part_rejects_octal_leading_zero() -> None:
    assert _is_bare_decimal_legacy_ipv4_part("0177") is False


def test_is_bare_decimal_legacy_ipv4_part_rejects_hex_prefix() -> None:
    assert _is_bare_decimal_legacy_ipv4_part("0x7f") is False


def test_legacy_ipv4_not_blocked_yields_no_threat_legacy_state() -> None:
    pattern = re.compile(_LEGACY_IPV4_HOST_RE, re.IGNORECASE)
    threat, timed_out = sus_patterns_handler._check_regex_pattern(
        pattern,
        "http://8.8.8.8/",
        "203.0.113.9",
        time.monotonic(),
        "ssrf",
        state=_LEGACY_DETECTION_STATE,
    )
    assert threat is None
    assert timed_out is False


def test_legacy_ipv4_not_blocked_yields_no_threat_enhanced_state() -> None:
    pattern = re.compile(_LEGACY_IPV4_HOST_RE, re.IGNORECASE)
    state = _LEGACY_DETECTION_STATE._replace(compiler=PatternCompiler())
    threat, timed_out = sus_patterns_handler._check_regex_pattern(
        pattern,
        "http://8.8.8.8/",
        "203.0.113.9",
        time.monotonic(),
        "ssrf",
        state=state,
    )
    assert threat is None
    assert timed_out is False
