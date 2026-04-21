"""Tests for LanguageRouter — routes to EN or multilingual transformer."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.prompt_injection.language_detector import LanguageDetector
from guard_core.prompt_injection.language_router import LanguageRouter


def _make_detector(
    name: str,
    is_suspicious_value: bool = False,
    prediction: dict[str, Any] | None = None,
) -> MagicMock:
    detector = MagicMock()
    detector.model_name = name
    detector.is_suspicious = MagicMock(return_value=is_suspicious_value)
    detector.get_prediction = MagicMock(
        return_value=prediction or {"injection_score": 0.1}
    )
    return detector


@pytest.fixture
def language_detector() -> MagicMock:
    det = MagicMock(spec=LanguageDetector)
    det.detect = MagicMock(return_value="ENGLISH")
    return det


class TestRouting:
    def test_picks_english_detector_for_english(
        self, language_detector: MagicMock
    ) -> None:
        en = _make_detector("en-model", is_suspicious_value=True)
        mx = _make_detector("mx-model", is_suspicious_value=False)
        router = LanguageRouter(en, mx, language_detector=language_detector)

        assert router.is_suspicious("hello world") is True
        en.is_suspicious.assert_called_once_with("hello world")
        mx.is_suspicious.assert_not_called()

    def test_picks_multilingual_for_non_english(
        self, language_detector: MagicMock
    ) -> None:
        language_detector.detect = MagicMock(return_value="GERMAN")
        en = _make_detector("en-model", is_suspicious_value=False)
        mx = _make_detector("mx-model", is_suspicious_value=True)
        router = LanguageRouter(en, mx, language_detector=language_detector)

        assert router.is_suspicious("ignorieren Sie alles") is True
        mx.is_suspicious.assert_called_once_with("ignorieren Sie alles")
        en.is_suspicious.assert_not_called()

    def test_none_language_falls_back_to_english(
        self, language_detector: MagicMock
    ) -> None:
        language_detector.detect = MagicMock(return_value=None)
        en = _make_detector("en-model", is_suspicious_value=True)
        mx = _make_detector("mx-model")
        router = LanguageRouter(en, mx, language_detector=language_detector)

        assert router.is_suspicious("short") is True
        en.is_suspicious.assert_called_once()

    def test_custom_english_languages_set(self, language_detector: MagicMock) -> None:
        language_detector.detect = MagicMock(return_value="GERMAN")
        en = _make_detector("en-model", is_suspicious_value=True)
        mx = _make_detector("mx-model")
        router = LanguageRouter(
            en,
            mx,
            language_detector=language_detector,
            english_languages=frozenset({"ENGLISH", "GERMAN"}),
        )

        assert router.is_suspicious("anything") is True
        en.is_suspicious.assert_called_once()
        mx.is_suspicious.assert_not_called()


class TestGetPrediction:
    def test_returns_prediction_with_routed_language_annotation(
        self, language_detector: MagicMock
    ) -> None:
        en = _make_detector("en-model", prediction={"injection_score": 0.8})
        mx = _make_detector("mx-model")
        router = LanguageRouter(en, mx, language_detector=language_detector)

        result = router.get_prediction("english text")
        assert result["injection_score"] == pytest.approx(0.8)
        assert result["routed_language"] == "ENGLISH"
        assert result["model_name"] == "en-model"

    def test_existing_model_name_is_preserved(
        self, language_detector: MagicMock
    ) -> None:
        en = _make_detector(
            "en-model",
            prediction={"injection_score": 0.5, "model_name": "explicit"},
        )
        mx = _make_detector("mx-model")
        router = LanguageRouter(en, mx, language_detector=language_detector)

        result = router.get_prediction("english text")
        assert result["model_name"] == "explicit"


class TestDefaults:
    def test_defaults_language_detector_when_none(self) -> None:
        en = _make_detector("en-model")
        mx = _make_detector("mx-model")
        router = LanguageRouter(en, mx)
        assert isinstance(router.language_detector, LanguageDetector)

    def test_model_name_exposes_english_model(self) -> None:
        en = _make_detector("en-model")
        mx = _make_detector("mx-model")
        router = LanguageRouter(en, mx)
        assert router.model_name == "en-model"

    def test_model_name_falls_back_when_absent(self) -> None:
        en = MagicMock(spec=[])
        mx = MagicMock(spec=[])
        router = LanguageRouter(en, mx)
        assert router.model_name == "language_router"
