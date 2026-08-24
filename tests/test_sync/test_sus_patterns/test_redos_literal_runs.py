import pytest

from guard_core.sync.detection_engine._redos_literal_runs import (
    _adversarial_literal_runs,
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


def test_adversarial_literal_runs_keeps_escaped_non_alnum_char() -> None:
    assert _adversarial_literal_runs(r"\.") == ["."]
