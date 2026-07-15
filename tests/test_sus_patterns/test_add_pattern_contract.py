from guard_core.handlers.suspatterns_handler import SusPatternsManager


async def test_add_pattern_returns_false_on_invalid_regex() -> None:
    ok = await SusPatternsManager.add_pattern(r"invalid(regex", custom=True)
    assert ok is False
    assert r"invalid(regex" not in SusPatternsManager().custom_patterns


async def test_add_pattern_returns_false_on_unsafe_regex() -> None:
    ok = await SusPatternsManager.add_pattern(r"(a+)+$", custom=True)
    assert ok is False
    assert r"(a+)+$" not in SusPatternsManager().custom_patterns


async def test_add_pattern_returns_true_on_valid_pattern() -> None:
    ok = await SusPatternsManager.add_pattern(r"attackterm123", custom=True)
    assert ok is True
    assert r"attackterm123" in SusPatternsManager().custom_patterns
