"""Tests for LanguageDetector — lazy lingua wrapper with graceful fallback."""

from __future__ import annotations

import builtins
import logging
import sys
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.prompt_injection.language_detector import LanguageDetector


def _block_import(monkeypatch: pytest.MonkeyPatch, module_name: str) -> None:
    real_import = builtins.__import__

    def fake_import(
        name: str,
        globals: Any = None,
        locals: Any = None,
        fromlist: Any = (),
        level: int = 0,
    ) -> Any:
        if name == module_name or name.startswith(module_name + "."):
            raise ImportError(f"No module named {module_name!r}")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    if module_name in sys.modules:
        monkeypatch.delitem(sys.modules, module_name)


@pytest.fixture
def fake_lingua(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    import lingua

    class FakeLanguage:
        def __init__(self, name: str) -> None:
            self.name = name

    default_language = FakeLanguage("ENGLISH")

    class FakeDetector:
        def __init__(self, next_language: Any = default_language) -> None:
            self.next_language = next_language

        def detect_language_of(self, text: str) -> Any:
            return self.next_language

    class FakeBuilder:
        _detector = FakeDetector()

        @classmethod
        def from_all_languages(cls) -> FakeBuilder:
            return cls()

        def with_preloaded_language_models(self) -> FakeBuilder:
            return self

        def build(self) -> FakeDetector:
            return FakeBuilder._detector

    monkeypatch.setattr(lingua, "LanguageDetectorBuilder", FakeBuilder, raising=True)
    return MagicMock(builder=FakeBuilder, detector=FakeBuilder._detector)


class TestShortInput:
    def test_below_min_length_returns_none(self) -> None:
        det = LanguageDetector(min_length=20)
        assert det.detect("short") is None

    def test_min_length_default_avoids_triggering_load(self) -> None:
        det = LanguageDetector()
        det.detect("hi")
        assert det._detector is None


class TestMissingDependency:
    def test_load_sets_unavailable_when_lingua_missing(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        _block_import(monkeypatch, "lingua")
        det = LanguageDetector(min_length=5)
        with caplog.at_level(logging.INFO):
            assert det.detect("enough characters here") is None
        assert det._unavailable is True
        assert any(
            "lingua-language-detector not installed" in rec.message
            for rec in caplog.records
        )

    def test_subsequent_calls_are_noops_when_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _block_import(monkeypatch, "lingua")
        det = LanguageDetector(min_length=5)
        det.detect("enough characters here")
        det.detect("another enough characters text")
        assert det._detector is None


class TestDetection:
    def test_returns_uppercase_language_name(self, fake_lingua: MagicMock) -> None:
        det = LanguageDetector(min_length=5)
        assert det.detect("this is long enough") == "ENGLISH"

    def test_returns_none_when_lingua_says_unknown(
        self, fake_lingua: MagicMock
    ) -> None:
        fake_lingua.detector.next_language = None
        det = LanguageDetector(min_length=5)
        assert det.detect("whatever this is really") is None

    def test_detection_exception_is_swallowed(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        import lingua

        class BrokenDetector:
            def detect_language_of(self, text: str) -> Any:
                raise RuntimeError("engine crashed")

        class FakeBuilder:
            @classmethod
            def from_all_languages(cls) -> FakeBuilder:
                return cls()

            def with_preloaded_language_models(self) -> FakeBuilder:
                return self

            def build(self) -> BrokenDetector:
                return BrokenDetector()

        monkeypatch.setattr(
            lingua, "LanguageDetectorBuilder", FakeBuilder, raising=True
        )
        det = LanguageDetector(min_length=5)
        with caplog.at_level(logging.ERROR):
            assert det.detect("this is long enough") is None
        assert any("Language detection failed" in rec.message for rec in caplog.records)

    def test_load_exception_sets_unavailable(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        import lingua

        class BrokenBuilder:
            @classmethod
            def from_all_languages(cls) -> BrokenBuilder:
                raise RuntimeError("init failed")

        monkeypatch.setattr(
            lingua, "LanguageDetectorBuilder", BrokenBuilder, raising=True
        )
        det = LanguageDetector(min_length=5)
        with caplog.at_level(logging.ERROR):
            assert det.detect("this is long enough") is None
        assert det._unavailable is True
        assert any("Failed to load lingua" in rec.message for rec in caplog.records)


class TestLazyLoading:
    def test_load_is_idempotent(self, fake_lingua: MagicMock) -> None:
        det = LanguageDetector(min_length=5)
        det.detect("this is long enough")
        first = det._detector
        det.detect("another long enough input")
        assert det._detector is first
