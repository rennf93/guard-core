import pytest

from guard_core.sync.detection_engine.preprocessor import ContentPreprocessor


@pytest.fixture
def pp() -> ContentPreprocessor:
    return ContentPreprocessor(max_content_length=2000, preserve_attack_patterns=True)


def test_base64_payload_decoded(pp: ContentPreprocessor) -> None:
    payload = "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
    result = pp.preprocess(f"data: {payload}")
    assert "<script" in result.lower()


def test_hex_escape_decoded(pp: ContentPreprocessor) -> None:
    payload = r"\x3cscript\x3ealert(1)\x3c/script\x3e"
    result = pp.preprocess(payload)
    assert "<script" in result.lower()


def test_js_unicode_escape_decoded(pp: ContentPreprocessor) -> None:
    payload = r"\u003cscript\u003ealert(1)\u003c/script\u003e"
    result = pp.preprocess(payload)
    assert "<script" in result.lower()


def test_sql_block_comment_retained_not_fused(pp: ContentPreprocessor) -> None:
    payload = "SELE/**/CT password FRO/**/M users"
    result = pp.preprocess(payload)
    assert "/**/" in result
    assert "select" not in result.lower()


def test_sql_line_comment_stripped(pp: ContentPreprocessor) -> None:
    payload = "SELECT password -- harmless\nFROM users"
    result = pp.preprocess(payload)
    assert "from users" in result.lower()


def test_decode_iteration_cap_holds(pp: ContentPreprocessor) -> None:
    payload = "%2525253c" * 50
    result = pp.preprocess(payload)
    assert isinstance(result, str)


def test_hex_escape_invalid_value(pp: ContentPreprocessor) -> None:
    payload = r"\xGG"
    result = pp.preprocess(payload)
    assert isinstance(result, str)


def test_unicode_escape_invalid_value(pp: ContentPreprocessor) -> None:
    payload = r"\uZZZZ"
    result = pp.preprocess(payload)
    assert isinstance(result, str)


def test_base64_invalid_token_preserved(pp: ContentPreprocessor) -> None:
    payload = "not-valid-base64-but-long-enough-to-match!@#$%^&*()"
    result = pp.preprocess(payload)
    assert isinstance(result, str)


def test_base64_non_printable_preserved(pp: ContentPreprocessor) -> None:
    import base64

    binary_data = bytes(range(32))
    token = base64.b64encode(binary_data).decode("ascii")
    result = pp.preprocess(f"data: {token}")
    assert isinstance(result, str)


def test_sql_block_and_line_comments_combined(pp: ContentPreprocessor) -> None:
    payload = "SELECT/*comment*/ password -- line comment\nFROM users"
    result = pp.preprocess(payload)
    assert "select" in result.lower()
    assert "from" in result.lower()


def test_hex_escape_all_valid_chars(pp: ContentPreprocessor) -> None:
    payload = r"\x41\x42\x43"
    result = pp.preprocess(payload)
    assert "abc" in result.lower()


def test_decode_hex_escapes_directly(pp: ContentPreprocessor) -> None:
    assert pp._decode_hex_escapes(r"\x41\x42") == "AB"


def test_decode_unicode_escapes_directly(pp: ContentPreprocessor) -> None:
    assert pp._decode_unicode_escapes(r"AB") == "AB"


def test_strip_sql_comments_block(pp: ContentPreprocessor) -> None:
    assert pp._strip_sql_comments("SEL/*x*/ECT") == "SEL/*x*/ECT"


def test_strip_sql_comments_line(pp: ContentPreprocessor) -> None:
    result = pp._strip_sql_comments("SELECT -- comment\nFROM")
    assert "FROM" in result


def test_strip_sql_comments_hash(pp: ContentPreprocessor) -> None:
    result = pp._strip_sql_comments("SELECT # comment\nFROM")
    assert "FROM" in result


def test_decode_base64_candidates_valid(pp: ContentPreprocessor) -> None:
    import base64

    token = base64.b64encode(b"<script>alert(1)</script>").decode("ascii")
    result = pp._decode_base64_candidates(token)
    assert "<script>" in result


def test_decode_base64_candidates_returns_token_when_decode_fails(
    pp: ContentPreprocessor, monkeypatch: pytest.MonkeyPatch
) -> None:
    import base64

    def raise_value_error(*args: object, **kwargs: object) -> bytes:
        raise ValueError("forced decode failure")

    monkeypatch.setattr(base64, "b64decode", raise_value_error)

    payload = "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
    result = pp._decode_base64_candidates(payload)
    assert result == payload


def test_hex_escape_value_error_path(pp: ContentPreprocessor) -> None:
    from unittest.mock import patch

    with patch("builtins.chr", side_effect=ValueError("invalid")):
        result = pp._decode_hex_escapes("\\x41")
    assert result == "\\x41"


def test_unicode_escape_value_error_path(pp: ContentPreprocessor) -> None:
    from unittest.mock import patch

    with patch("builtins.chr", side_effect=ValueError("invalid")):
        result = pp._decode_unicode_escapes("\\u0041")
    assert result == "\\u0041"


def test_sql_between_token_comment_retained(
    pp: ContentPreprocessor,
) -> None:
    payload = "WHERE id=1/**/OR/**/x=2"
    result = pp.preprocess(payload)
    assert "/**/" in result
    assert "1or" not in result.lower()


def test_sql_lowercase_keyword_comment_retained(
    pp: ContentPreprocessor,
) -> None:
    payload = "sele/**/ct password fro/**/m users"
    result = pp.preprocess(payload)
    assert "/**/" in result
    assert "select" not in result.lower()


def test_sql_uppercase_keyword_comment_retained(
    pp: ContentPreprocessor,
) -> None:
    payload = "WHERE id=1 OR/**/x=2"
    result = pp.preprocess(payload)
    assert "/**/" in result
    assert "orx" not in result.lower()


def test_truncate_preserves_tail_content_after_attack_region(
    pp: ContentPreprocessor,
) -> None:
    pp2 = ContentPreprocessor(max_content_length=300, preserve_attack_patterns=True)
    attack = "<script>x</script>"
    safe_tail = "A" * 400
    payload = attack + safe_tail
    result = pp2.preprocess(payload)
    assert "<script" in result.lower()
    assert len(result) <= 300
    assert len(result) > len(attack)
