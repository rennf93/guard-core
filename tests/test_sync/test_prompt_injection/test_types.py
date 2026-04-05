import pytest

from guard_core.sync.prompt_injection.types import (
    InjectionPattern,
    PatternCategory,
    PromptInjectionAttempt,
)


class TestPatternCategory:
    def test_all_categories_exist(self) -> None:
        categories = list(PatternCategory)
        assert len(categories) == 8

    def test_category_keys(self) -> None:
        assert PatternCategory.INSTRUCTION_OVERRIDE.key == "instruction_override"
        assert PatternCategory.ROLE_SWITCHING.key == "role_switching"
        assert PatternCategory.JAILBREAK_ATTEMPTS.key == "jailbreak_attempts"

    def test_category_weights(self) -> None:
        assert PatternCategory.INSTRUCTION_OVERRIDE.default_weight == 10
        assert PatternCategory.DELIMITER_CONFUSION.default_weight == 5
        assert PatternCategory.JAILBREAK_ATTEMPTS.default_weight == 10


class TestInjectionPattern:
    def test_basic_pattern(self) -> None:
        pattern = InjectionPattern(
            pattern=r"\btest\b",
            category=PatternCategory.INSTRUCTION_OVERRIDE,
        )
        assert pattern.enabled is True
        assert pattern.weight == 1.0
        assert pattern.confidence == 1.0
        assert pattern.pattern_id is not None

    def test_pattern_match(self) -> None:
        pattern = InjectionPattern(
            pattern=r"\bignore\s+previous\b",
            category=PatternCategory.INSTRUCTION_OVERRIDE,
        )
        matches = pattern.match("Please ignore previous instructions")
        assert len(matches) == 1

    def test_pattern_no_match(self) -> None:
        pattern = InjectionPattern(
            pattern=r"\bignore\s+previous\b",
            category=PatternCategory.INSTRUCTION_OVERRIDE,
        )
        matches = pattern.match("Hello world")
        assert len(matches) == 0

    def test_disabled_pattern_no_match(self) -> None:
        pattern = InjectionPattern(
            pattern=r"\btest\b",
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            enabled=False,
        )
        matches = pattern.match("test")
        assert len(matches) == 0

    def test_get_score(self) -> None:
        pattern = InjectionPattern(
            pattern=r"\btest\b",
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=2.0,
            confidence=0.8,
        )
        # 10 (category weight) * 2.0 (weight) * 0.8 (confidence) = 16.0
        assert pattern.get_score() == 16.0

    def test_auto_generate_pattern_id(self) -> None:
        pattern = InjectionPattern(
            pattern=r"\btest\b",
            category=PatternCategory.ROLE_SWITCHING,
        )
        assert pattern.pattern_id is not None
        assert "role_switching" in pattern.pattern_id

    def test_explicit_pattern_id(self) -> None:
        pattern = InjectionPattern(
            pattern=r"\btest\b",
            category=PatternCategory.ROLE_SWITCHING,
            pattern_id="my_custom_id",
        )
        assert pattern.pattern_id == "my_custom_id"

    def test_invalid_regex_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid regex pattern"):
            InjectionPattern(
                pattern=r"[invalid",
                category=PatternCategory.INSTRUCTION_OVERRIDE,
            )

    def test_weight_clamped(self) -> None:
        pattern = InjectionPattern(
            pattern=r"\btest\b",
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=-1.0,
        )
        assert pattern.weight == 0.0

    def test_confidence_clamped(self) -> None:
        pattern = InjectionPattern(
            pattern=r"\btest\b",
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            confidence=1.5,
        )
        assert pattern.confidence == 1.0

    def test_case_insensitive_match(self) -> None:
        pattern = InjectionPattern(
            pattern=r"\bIGNORE\b",
            category=PatternCategory.INSTRUCTION_OVERRIDE,
        )
        matches = pattern.match("please ignore this")
        assert len(matches) == 1


class TestPromptInjectionAttempt:
    def test_exception_message(self) -> None:
        exc = PromptInjectionAttempt(
            matched_patterns=["pattern1"],
            detection_layer="pattern",
            threat_score=0.85,
        )
        assert "pattern1" in str(exc)
        assert "0.85" in str(exc)

    def test_to_dict(self) -> None:
        exc = PromptInjectionAttempt(
            matched_patterns=["p1", "p2"],
            detection_layer="multi_layer",
            threat_score=0.9,
            detection_metadata={"key": "value"},
        )
        d = exc.to_dict()
        assert d["matched_patterns"] == ["p1", "p2"]
        assert d["detection_layer"] == "multi_layer"
        assert d["threat_score"] == 0.9
        assert d["detection_metadata"] == {"key": "value"}

    def test_default_metadata(self) -> None:
        exc = PromptInjectionAttempt(
            matched_patterns=[],
            detection_layer="test",
            threat_score=0.0,
        )
        assert exc.detection_metadata == {}
