from typing import Any

from guard_core.prompt_injection.language_detector import LanguageDetector


class LanguageRouter:
    """Routes classification between an English and a multilingual detector.

    Wraps two `TransformerDetector`-compatible objects (anything exposing
    `is_suspicious(text) -> bool` and `get_prediction(text) -> dict`).
    Selection uses `LanguageDetector`; when language detection is
    unavailable or inconclusive, the `english_detector` is used.

    The `english_languages` set controls which lingua labels route to
    the English detector; the default covers English only. Adding more
    entries lets you route, e.g., German or French traffic to a model
    that handles those languages better than the multilingual default.
    """

    def __init__(
        self,
        english_detector: Any,
        multilingual_detector: Any,
        language_detector: LanguageDetector | None = None,
        english_languages: frozenset[str] = frozenset({"ENGLISH"}),
    ) -> None:
        self.english_detector = english_detector
        self.multilingual_detector = multilingual_detector
        self.language_detector = language_detector or LanguageDetector()
        self.english_languages = english_languages
        self.model_name = getattr(english_detector, "model_name", "language_router")

    def _pick(self, text: str) -> Any:
        language = self.language_detector.detect(text)
        if language is None or language in self.english_languages:
            return self.english_detector
        return self.multilingual_detector

    def is_suspicious(self, text: str) -> bool:
        return bool(self._pick(text).is_suspicious(text))

    def get_prediction(self, text: str) -> dict[str, Any]:
        detector = self._pick(text)
        prediction: dict[str, Any] = detector.get_prediction(text)
        prediction.setdefault("model_name", getattr(detector, "model_name", "unknown"))
        prediction["routed_language"] = self.language_detector.detect(text)
        return prediction
