import pytest

from guard_core.prompt_injection import InjectionPattern, PatternCategory


class TestInjectionPatternValidation:
    def test_negative_weight_clamped_to_zero(self) -> None:
        p = InjectionPattern(
            pattern=r"\btest\b",
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=-5.0,
        )
        assert p.weight == 0.0

    def test_confidence_above_one_clamped(self) -> None:
        p = InjectionPattern(
            pattern=r"\btest\b",
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            confidence=5.0,
        )
        assert p.confidence == 1.0

    def test_invalid_regex_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid regex"):
            InjectionPattern(
                pattern="[unclosed",
                category=PatternCategory.INSTRUCTION_OVERRIDE,
            )


class TestMatching:
    def test_disabled_pattern_returns_empty(self) -> None:
        p = InjectionPattern(
            pattern=r"\btest\b",
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            enabled=False,
        )
        assert p.match("test text") == []


class TestSerialization:
    def test_from_dict_rejects_unknown_category(self) -> None:
        with pytest.raises(ValueError, match="Invalid category"):
            InjectionPattern.from_dict(
                {"pattern": r"\btest\b", "category": "not_a_category"}
            )
