import pytest

from guard_core.core.validation.path_matching import (
    normalize_url_path,
    path_is_excluded,
)

DEFAULT_EXCLUDES = [
    "/docs",
    "/redoc",
    "/openapi.json",
    "/openapi.yaml",
    "/favicon.ico",
    "/static",
]


def _percent_encode_bytes(value: str) -> str:
    return "".join(f"%{b:02X}" for b in value.encode("utf-8"))


def _nested_percent_encode(value: str, layers: int) -> str:
    result = value
    for _ in range(layers):
        result = _percent_encode_bytes(result)
    return result


EXPLOIT_CASES: list[tuple[str, bool]] = [
    ("/staticadmin", False),
    ("/redoc-admin/delete-all", False),
    ("/static../.aws/credentials", False),
    ("/docs../../etc/passwd", False),
    ("/static/../../../root/.ssh/id_rsa", False),
    ("/static//../../etc/passwd", False),
]


@pytest.mark.parametrize("url_path,expected", EXPLOIT_CASES)
def test_path_is_excluded_rejects_known_exploit_paths(
    url_path: str, expected: bool
) -> None:
    assert path_is_excluded(url_path, DEFAULT_EXCLUDES) is expected


BOUNDARY_CASES: list[tuple[str, bool]] = [
    ("/static", True),
    ("/static/", True),
    ("/static/js/app.js", True),
    ("/staticfoo", False),
    ("/static/a/../b.js", True),
    ("/static//js//app.js", True),
]


@pytest.mark.parametrize("url_path,expected", BOUNDARY_CASES)
def test_path_is_excluded_boundary_matches(url_path: str, expected: bool) -> None:
    assert path_is_excluded(url_path, ["/static"]) is expected


def test_path_is_excluded_empty_exclude_list_excludes_nothing() -> None:
    assert path_is_excluded("/static", []) is False
    assert path_is_excluded("/anything/at/all", []) is False


def test_path_is_excluded_root_exclusion_matches_every_path() -> None:
    assert path_is_excluded("/anything", ["/"]) is True
    assert path_is_excluded("/", ["/"]) is True


def test_path_is_excluded_config_with_trailing_slash_behaves_like_no_slash() -> None:
    assert path_is_excluded("/static", ["/static/"]) is True
    assert path_is_excluded("/static/js/app.js", ["/static/"]) is True
    assert path_is_excluded("/staticfoo", ["/static/"]) is False


def test_path_is_excluded_config_without_leading_slash_gets_normalized() -> None:
    assert path_is_excluded("/static", ["static"]) is True
    assert path_is_excluded("/static/js/app.js", ["static"]) is True
    assert path_is_excluded("/staticfoo", ["static"]) is False


def test_path_is_excluded_skips_unresolvable_configured_entry() -> None:
    unresolvable = _nested_percent_encode("..", 5)
    assert path_is_excluded("/health", ["/health", unresolvable]) is True
    assert path_is_excluded("/other", [unresolvable]) is False


def test_path_is_excluded_percent_encoded_dot_segment_traversal_escapes() -> None:
    assert path_is_excluded("/static/%2e%2e/secret", ["/static"]) is False


def test_path_is_excluded_mixed_case_percent_encoding_escapes() -> None:
    assert path_is_excluded("/static/%2E%2e/secret", ["/static"]) is False


def test_path_is_excluded_percent_encoded_slash_traversal_escapes() -> None:
    encoded = "/static%2f..%2f..%2fetc%2fpasswd"
    assert path_is_excluded(encoded, ["/static"]) is False


def test_path_is_excluded_double_encoded_traversal_escapes() -> None:
    encoded_dotdot = _nested_percent_encode("..", 2)
    url_path = f"/static/{encoded_dotdot}/secret"
    assert path_is_excluded(url_path, ["/static"]) is False


def test_path_is_excluded_unicode_overlong_encoding_fails_closed() -> None:
    overlong_slash = "%c0%af"
    url_path = f"/static{overlong_slash}..{overlong_slash}..{overlong_slash}etc"
    assert path_is_excluded(url_path, ["/static"]) is False


def test_normalize_url_path_leaves_plain_path_untouched() -> None:
    assert normalize_url_path("/health") == "/health"


def test_normalize_url_path_collapses_dot_segments() -> None:
    assert normalize_url_path("/static/a/../b.js") == "/static/b.js"


def test_normalize_url_path_absorbs_traversal_above_root() -> None:
    assert (
        normalize_url_path("/static/../../../root/.ssh/id_rsa") == "/root/.ssh/id_rsa"
    )


def test_normalize_url_path_treats_backslash_as_separator() -> None:
    assert normalize_url_path("/static\\..\\..\\etc\\passwd") == "/etc/passwd"


def test_normalize_url_path_decodes_percent_encoded_slash_as_boundary() -> None:
    assert normalize_url_path("/static%2Fjs") == "/static/js"


def test_normalize_url_path_resolves_nested_encoding_within_round_cap() -> None:
    encoded = _nested_percent_encode("..", 4)
    assert normalize_url_path(f"/static/{encoded}/x") == "/x"


def test_normalize_url_path_fails_closed_beyond_round_cap() -> None:
    encoded = _nested_percent_encode("..", 5)
    assert normalize_url_path(f"/static/{encoded}/x") is None


def test_normalize_url_path_fails_closed_on_overlong_utf8() -> None:
    assert normalize_url_path("/static%c0%af..") is None


def test_normalize_url_path_fails_closed_on_invalid_utf8_continuation() -> None:
    assert normalize_url_path("/static%e0%80%af") is None


def test_normalize_url_path_leaves_malformed_percent_sequence_literal() -> None:
    assert normalize_url_path("/static%zz/js") == "/static%zz/js"
