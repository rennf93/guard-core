from guard_core.detection_engine._redos_unreachable_terminator import (
    _terminator_chars_at,
)


def test_terminator_chars_at_returns_positive_char_class() -> None:
    assert _terminator_chars_at("[abc]", 0) == {"a", "b", "c"}


def test_terminator_chars_at_returns_none_for_negated_class() -> None:
    assert _terminator_chars_at("[^abc]", 0) is None


def test_terminator_chars_at_returns_none_for_empty_class() -> None:
    assert _terminator_chars_at("[]", 0) is None


def test_terminator_chars_at_returns_none_past_end() -> None:
    assert _terminator_chars_at("[abc]", 5) is None


def test_terminator_chars_at_returns_singleton_for_literal() -> None:
    assert _terminator_chars_at("x", 0) == {"x"}
