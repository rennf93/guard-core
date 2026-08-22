import pytest

from guard_core.detection_engine._redos_literal_runs import (
    _brace_quantifier_span_allows_zero,
)


@pytest.mark.parametrize(
    "text,k,expected",
    [
        ("a{3", 1, (1, False)),
        ("a{x,3}b", 1, (1, False)),
        ("a{3}b", 1, (4, False)),
        ("a{0,3}b", 1, (6, True)),
        ("a{,3}b", 1, (5, True)),
        ("a{3}?b", 1, (5, False)),
    ],
)
def test_brace_quantifier_span_allows_zero_branches(
    text: str, k: int, expected: tuple[int, bool]
) -> None:
    assert _brace_quantifier_span_allows_zero(text, k) == expected
