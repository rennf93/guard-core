import base64

import pytest

from guard_core.detection_engine import base64_view
from guard_core.detection_engine.base64_view import build_short_base64_additive_view
from guard_core.detection_engine.preprocessor import ContentPreprocessor


def test_printable_ratio_empty_text_is_zero() -> None:
    assert base64_view._printable_ratio("") == 0.0


def test_build_short_base64_additive_view_empty_content() -> None:
    preprocessor = ContentPreprocessor()

    assert build_short_base64_additive_view(preprocessor, "") == ""


def test_build_short_base64_additive_view_no_candidates_below_min_length() -> None:
    preprocessor = ContentPreprocessor()

    result = build_short_base64_additive_view(preprocessor, "ab cd ef gh")

    assert result == ""


def test_build_short_base64_additive_view_skips_undecodable_token() -> None:
    preprocessor = ContentPreprocessor()

    result = build_short_base64_additive_view(preprocessor, "prefix abcde suffix")

    assert result == ""


def test_build_short_base64_additive_view_skips_non_utf8_decode() -> None:
    preprocessor = ContentPreprocessor()
    token = base64.b64encode(bytes([0xFF, 0xFE, 0xFD])).decode()

    result = build_short_base64_additive_view(preprocessor, f"prefix {token} end")

    assert result == ""


def test_build_short_base64_additive_view_skips_low_printable_ratio() -> None:
    preprocessor = ContentPreprocessor()
    token = base64.b64encode(bytes([1, 2, 3])).decode()

    result = build_short_base64_additive_view(preprocessor, f"prefix {token} end")

    assert result == ""


def test_build_short_base64_additive_view_skips_decode_without_marker_char() -> None:
    preprocessor = ContentPreprocessor()
    token = base64.b64encode(b"abc").decode()

    result = build_short_base64_additive_view(preprocessor, f"prefix {token} end")

    assert result == ""


def test_build_short_base64_additive_view_ignores_token_at_run_floor() -> None:
    preprocessor = ContentPreprocessor()
    token = base64.b64encode(b"$AAAAAAA}").decode()
    assert len(token) == 12

    result = build_short_base64_additive_view(preprocessor, f"prefix {token} end")

    assert result == ""


def test_build_short_base64_additive_view_recovers_ssti_dollar_brace_probe() -> None:
    preprocessor = ContentPreprocessor()
    token = base64.b64encode(b"${7*7}").decode()

    result = build_short_base64_additive_view(preprocessor, f"prefix {token} end")

    assert result == "${7*7}"


def test_build_short_base64_additive_view_recovers_ssti_hash_brace_probe() -> None:
    preprocessor = ContentPreprocessor()
    token = base64.b64encode(b"#{7*7}").decode()

    result = build_short_base64_additive_view(preprocessor, f"prefix {token} end")

    assert result == "#{7*7}"


def test_build_short_base64_additive_view_joins_multiple_fragments() -> None:
    preprocessor = ContentPreprocessor()
    dollar_token = base64.b64encode(b"${7*7}").decode()
    hash_token = base64.b64encode(b"#{7*7}").decode()

    result = build_short_base64_additive_view(
        preprocessor, f"a={dollar_token}&b={hash_token}"
    )

    assert result == "${7*7}\n#{7*7}"


def test_build_short_base64_additive_view_never_carries_original_text() -> None:
    preprocessor = ContentPreprocessor()
    token = base64.b64encode(b"${7*7}").decode()
    content = f"SELECT a coffee from the menu {token} and discuss my order"

    result = build_short_base64_additive_view(preprocessor, content)

    assert result == "${7*7}"
    assert "SELECT" not in result
    assert "coffee" not in result


def test_build_short_base64_additive_view_stops_at_candidate_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preprocessor = ContentPreprocessor()
    monkeypatch.setattr(base64_view, "MAX_SHORT_BASE64_CANDIDATES", 1)
    dollar_token = base64.b64encode(b"${7*7}").decode()
    hash_token = base64.b64encode(b"#{7*7}").decode()

    result = build_short_base64_additive_view(
        preprocessor, f"a={dollar_token}&b={hash_token}"
    )

    assert result == "${7*7}"


def test_preprocess_short_base64_additive_view_delegates_to_base64_view() -> None:
    preprocessor = ContentPreprocessor()
    token = base64.b64encode(b"${7*7}").decode()

    result = preprocessor.preprocess_short_base64_additive_view(f"prefix {token} end")

    assert result == "${7*7}"
