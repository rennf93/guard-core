import re

from guard_core.sync.detection_engine.scan_window import (
    bounded_finditer,
    bounded_search,
)


def test_bounded_search_matches_simple_prefix_gap_terminator() -> None:
    compiled = re.compile(r"<script[^>]*>")
    prefix = re.compile(r"<script")
    terminator = re.compile(r">")

    match = bounded_search("<script src=x>", compiled, prefix, terminator)
    raw = compiled.search("<script src=x>")

    assert match is not None
    assert raw is not None
    assert match.group() == "<script src=x>"
    assert match.span() == raw.span()


def test_bounded_search_returns_none_when_prefix_absent() -> None:
    compiled = re.compile(r"<script[^>]*>")
    prefix = re.compile(r"<script")
    terminator = re.compile(r">")

    assert bounded_search("no tags here>", compiled, prefix, terminator) is None


def test_bounded_search_returns_none_when_terminator_absent() -> None:
    compiled = re.compile(r"<script[^>]*>")
    prefix = re.compile(r"<script")
    terminator = re.compile(r">")

    assert bounded_search("<script src=x", compiled, prefix, terminator) is None


def test_bounded_search_returns_none_when_the_only_candidate_fails() -> None:
    compiled = re.compile(r"X\d+Y")
    prefix = re.compile(r"X")
    terminator = re.compile(r"Y")

    assert bounded_search("XaY", compiled, prefix, terminator) is None


def test_bounded_search_returns_none_when_every_prefix_starts_after_the_ceiling() -> (
    None
):
    compiled = re.compile(r"X\d+Y")
    prefix = re.compile(r"X")
    terminator = re.compile(r"Y")

    assert bounded_search(">X", compiled, prefix, terminator) is None


def test_bounded_search_widens_past_a_terminator_that_does_not_complete_the_match() -> (
    None
):
    compiled = re.compile(r"<!TAG[^>]+MID[^>]+>")
    prefix = re.compile(r"<!TAG")
    terminator = re.compile(r">")
    text = '<!TAG a MID "b" <!TAG z MID "c">'

    raw = compiled.search(text)
    match = bounded_search(text, compiled, prefix, terminator)

    assert match is not None
    assert raw is not None
    assert match.span() == raw.span()


def test_bounded_search_gives_up_on_an_adversarial_fill_with_no_terminator() -> None:
    compiled = re.compile(r"<!TAG[^>]+MID[^>]+>")
    prefix = re.compile(r"<!TAG")
    terminator = re.compile(r">")
    adversarial = "<!TAG a MID b" * 5000

    assert bounded_search(adversarial, compiled, prefix, terminator) is None


def test_bounded_finditer_yields_every_non_overlapping_match() -> None:
    compiled = re.compile(r"X[^Y]*Y")
    prefix = re.compile(r"X")
    terminator = re.compile(r"Y")
    text = "aXaYbXbYc"

    matches = list(bounded_finditer(text, compiled, prefix, terminator))

    assert [m.group() for m in matches] == ["XaY", "XbY"]
    assert [m.span() for m in matches] == [m.span() for m in compiled.finditer(text)]


def test_bounded_finditer_matches_raw_search_when_a_prefix_is_shadowed() -> None:
    compiled = re.compile(r"X[^Y]*Y")
    prefix = re.compile(r"X")
    terminator = re.compile(r"Y")
    text = "XXY"

    matches = list(bounded_finditer(text, compiled, prefix, terminator))
    raw = compiled.search(text)

    assert raw is not None
    assert [m.span() for m in matches] == [raw.span()]


def test_bounded_finditer_yields_zero_width_matches_and_advances_past_them() -> None:
    compiled = re.compile(r"(?=Y)")
    prefix = re.compile(r"")
    terminator = re.compile(r"Y")
    text = "aYbYc"

    matches = list(bounded_finditer(text, compiled, prefix, terminator))

    assert [m.span() for m in matches] == [(1, 1), (3, 3)]
    assert [m.span() for m in matches] == [m.span() for m in compiled.finditer(text)]
