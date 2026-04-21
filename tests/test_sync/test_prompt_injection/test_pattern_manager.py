import json
from pathlib import Path

import pytest

from guard_core.sync.prompt_injection import (
    InjectionPattern,
    PatternCategory,
    PatternManager,
)


@pytest.fixture
def sample_pattern() -> InjectionPattern:
    return InjectionPattern(
        pattern_id="p_test",
        pattern=r"\btest\b",
        category=PatternCategory.INSTRUCTION_OVERRIDE,
        weight=1.0,
        confidence=1.0,
        description="test pattern",
    )


@pytest.fixture
def manager_with_pattern(sample_pattern: InjectionPattern) -> PatternManager:
    m = PatternManager()
    m.add_pattern(sample_pattern, persist=False)
    return m


class TestAddRemoveGet:
    def test_add_duplicate_raises(
        self, manager_with_pattern: PatternManager, sample_pattern: InjectionPattern
    ) -> None:
        with pytest.raises(ValueError, match="Pattern ID already exists"):
            manager_with_pattern.add_pattern(sample_pattern, persist=False)

    def test_remove_unknown_returns_false(
        self, manager_with_pattern: PatternManager
    ) -> None:
        assert manager_with_pattern.remove_pattern("missing", persist=False) is False

    def test_remove_known_returns_true(
        self, manager_with_pattern: PatternManager
    ) -> None:
        assert manager_with_pattern.remove_pattern("p_test", persist=False) is True
        assert manager_with_pattern.get_pattern("p_test") is None

    def test_get_pattern_returns_none(
        self, manager_with_pattern: PatternManager
    ) -> None:
        assert manager_with_pattern.get_pattern("missing") is None


class TestEnableDisable:
    def test_enable_missing(self, manager_with_pattern: PatternManager) -> None:
        assert manager_with_pattern.enable_pattern("missing", persist=False) is False

    def test_disable_missing(self, manager_with_pattern: PatternManager) -> None:
        assert manager_with_pattern.disable_pattern("missing", persist=False) is False

    def test_disable_then_enable(self, manager_with_pattern: PatternManager) -> None:
        assert manager_with_pattern.disable_pattern("p_test", persist=False) is True
        disabled = manager_with_pattern.get_pattern("p_test")
        assert disabled is not None
        assert disabled.enabled is False
        assert manager_with_pattern.enable_pattern("p_test", persist=False) is True
        enabled = manager_with_pattern.get_pattern("p_test")
        assert enabled is not None
        assert enabled.enabled is True


class TestUpdate:
    def test_update_weight_missing(self, manager_with_pattern: PatternManager) -> None:
        assert (
            manager_with_pattern.update_pattern_weight("missing", 2.0, persist=False)
            is False
        )

    def test_update_weight_negative_raises(
        self, manager_with_pattern: PatternManager
    ) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            manager_with_pattern.update_pattern_weight("p_test", -1.0, persist=False)

    def test_update_weight_success(self, manager_with_pattern: PatternManager) -> None:
        assert (
            manager_with_pattern.update_pattern_weight("p_test", 2.5, persist=False)
            is True
        )
        updated = manager_with_pattern.get_pattern("p_test")
        assert updated is not None
        assert updated.weight == 2.5

    def test_update_confidence_missing(
        self, manager_with_pattern: PatternManager
    ) -> None:
        assert (
            manager_with_pattern.update_pattern_confidence(
                "missing", 0.5, persist=False
            )
            is False
        )

    def test_update_confidence_out_of_range(
        self, manager_with_pattern: PatternManager
    ) -> None:
        with pytest.raises(ValueError, match="between 0.0 and 1.0"):
            manager_with_pattern.update_pattern_confidence("p_test", 1.5, persist=False)

    def test_update_confidence_success(
        self, manager_with_pattern: PatternManager
    ) -> None:
        assert (
            manager_with_pattern.update_pattern_confidence("p_test", 0.5, persist=False)
            is True
        )
        updated = manager_with_pattern.get_pattern("p_test")
        assert updated is not None
        assert updated.confidence == 0.5


class TestQueries:
    def test_get_patterns_by_category_enabled_only(
        self, manager_with_pattern: PatternManager
    ) -> None:
        manager_with_pattern.disable_pattern("p_test", persist=False)
        patterns = manager_with_pattern.get_patterns_by_category(
            PatternCategory.INSTRUCTION_OVERRIDE, enabled_only=True
        )
        assert patterns == []

    def test_get_patterns_by_category_all(
        self, manager_with_pattern: PatternManager
    ) -> None:
        manager_with_pattern.disable_pattern("p_test", persist=False)
        patterns = manager_with_pattern.get_patterns_by_category(
            PatternCategory.INSTRUCTION_OVERRIDE, enabled_only=False
        )
        assert len(patterns) == 1


class TestTestPattern:
    def test_test_pattern_missing(self, manager_with_pattern: PatternManager) -> None:
        result = manager_with_pattern.test_pattern("missing", "some text")
        assert result == {"error": "Pattern not found"}

    def test_test_pattern_match(self, manager_with_pattern: PatternManager) -> None:
        result = manager_with_pattern.test_pattern("p_test", "this is a test string")
        assert result["matched"] is True
        assert result["match_count"] == 1
        assert result["matches"][0]["text"] == "test"
        assert result["category"] == "instruction_override"


class TestStatsAndReport:
    def test_get_pattern_stats(self, manager_with_pattern: PatternManager) -> None:
        stats = manager_with_pattern.get_pattern_stats()
        assert stats["total_patterns"] == 1
        assert stats["enabled_patterns"] == 1
        assert stats["disabled_patterns"] == 0
        assert stats["patterns_by_category"]["instruction_override"] == 1

    def test_effectiveness_report(self, manager_with_pattern: PatternManager) -> None:
        pattern = manager_with_pattern.get_pattern("p_test")
        assert pattern is not None
        pattern.match("test test hello")
        pattern.report_false_positive()
        report = manager_with_pattern.get_effectiveness_report()
        assert report["summary"]["total_patterns"] == 1
        assert report["summary"]["total_matches"] == 2
        assert report["summary"]["total_false_positives"] == 1
        assert report["patterns"][0]["true_positives"] == 1
        assert report["patterns"][0]["precision"] == 0.5


class TestPersistence:
    def test_save_without_file_raises(
        self, manager_with_pattern: PatternManager
    ) -> None:
        with pytest.raises(ValueError, match="No pattern file configured"):
            manager_with_pattern.save_patterns()

    def test_load_without_file_raises(
        self, manager_with_pattern: PatternManager
    ) -> None:
        with pytest.raises(ValueError, match="No pattern file configured"):
            manager_with_pattern.load_patterns()

    def test_load_missing_file_raises(self, tmp_path: Path) -> None:
        m = PatternManager(pattern_file=tmp_path / "none.json")
        with pytest.raises(ValueError, match="Pattern file not found"):
            m.load_patterns()

    def test_save_and_reload_roundtrip(
        self,
        sample_pattern: InjectionPattern,
        tmp_path: Path,
    ) -> None:
        file = tmp_path / "patterns.json"
        m = PatternManager(pattern_file=file)
        m.add_pattern(sample_pattern)

        assert file.exists()
        payload = json.loads(file.read_text())
        assert payload["version"] == "1.0"
        assert len(payload["patterns"]) == 1

        m2 = PatternManager(pattern_file=file)
        assert m2.get_pattern("p_test") is not None

    def test_add_persists_when_file_set(
        self, sample_pattern: InjectionPattern, tmp_path: Path
    ) -> None:
        file = tmp_path / "patterns.json"
        m = PatternManager(pattern_file=file)
        m.add_pattern(sample_pattern)
        assert file.exists()

    def test_remove_persists(
        self, sample_pattern: InjectionPattern, tmp_path: Path
    ) -> None:
        file = tmp_path / "patterns.json"
        m = PatternManager(pattern_file=file)
        m.add_pattern(sample_pattern)
        m.remove_pattern("p_test")
        assert json.loads(file.read_text())["patterns"] == []

    def test_enable_disable_persist(
        self, sample_pattern: InjectionPattern, tmp_path: Path
    ) -> None:
        file = tmp_path / "patterns.json"
        m = PatternManager(pattern_file=file)
        m.add_pattern(sample_pattern)
        m.disable_pattern("p_test")
        m.enable_pattern("p_test")
        assert file.exists()

    def test_update_persist(
        self, sample_pattern: InjectionPattern, tmp_path: Path
    ) -> None:
        file = tmp_path / "patterns.json"
        m = PatternManager(pattern_file=file)
        m.add_pattern(sample_pattern)
        m.update_pattern_weight("p_test", 2.0)
        m.update_pattern_confidence("p_test", 0.8)
        assert file.exists()

    def test_clear_persists(
        self, sample_pattern: InjectionPattern, tmp_path: Path
    ) -> None:
        file = tmp_path / "patterns.json"
        m = PatternManager(pattern_file=file)
        m.add_pattern(sample_pattern)
        m.clear_all_patterns()
        assert len(m.patterns) == 0
        assert json.loads(file.read_text())["patterns"] == []

    def test_clear_without_file(self, manager_with_pattern: PatternManager) -> None:
        manager_with_pattern.clear_all_patterns()
        assert len(manager_with_pattern.patterns) == 0


class TestGetAllPatterns:
    def test_enabled_only_filters(self, manager_with_pattern: PatternManager) -> None:
        manager_with_pattern.disable_pattern("p_test", persist=False)
        assert manager_with_pattern.get_all_patterns(enabled_only=True) == []

    def test_all_includes_disabled(self, manager_with_pattern: PatternManager) -> None:
        manager_with_pattern.disable_pattern("p_test", persist=False)
        assert len(manager_with_pattern.get_all_patterns(enabled_only=False)) == 1


class TestBulkUpdate:
    def test_bulk_update_category_weights(
        self, manager_with_pattern: PatternManager
    ) -> None:
        count = manager_with_pattern.bulk_update_category_weights(
            PatternCategory.INSTRUCTION_OVERRIDE, 2.0, persist=False
        )
        assert count == 1
        updated = manager_with_pattern.get_pattern("p_test")
        assert updated is not None
        assert updated.weight == 2.0

    def test_bulk_update_no_match(self, manager_with_pattern: PatternManager) -> None:
        count = manager_with_pattern.bulk_update_category_weights(
            PatternCategory.JAILBREAK_ATTEMPTS, 2.0, persist=False
        )
        assert count == 0

    def test_bulk_update_persists(
        self, sample_pattern: InjectionPattern, tmp_path: Path
    ) -> None:
        file = tmp_path / "patterns.json"
        m = PatternManager(pattern_file=file)
        m.add_pattern(sample_pattern)
        m.bulk_update_category_weights(PatternCategory.INSTRUCTION_OVERRIDE, 3.0)
        assert file.exists()
