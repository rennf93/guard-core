import logging
from typing import Any

logger = logging.getLogger(__name__)


class LanguageDetector:
    """Thin wrapper around lingua-language-detector with lazy load.

    Exposes a minimal `detect(text) -> str | None` API that returns an
    uppercase ISO-639-1-ish language name (e.g. "ENGLISH", "GERMAN") or
    `None` when the input is too short or the library is unavailable.
    Callers can route transformer selection without depending directly
    on lingua's types; when the optional extra is not installed,
    detection is a no-op and the router falls through to its default.
    """

    def __init__(self, min_length: int = 20) -> None:
        self.min_length = min_length
        self._detector: Any = None
        self._unavailable: bool = False

    def _load(self) -> None:
        if self._detector is not None or self._unavailable:
            return
        try:
            from lingua import LanguageDetectorBuilder

            self._detector = (
                LanguageDetectorBuilder.from_all_languages()
                .with_preloaded_language_models()
                .build()
            )
        except ImportError:
            self._unavailable = True
            logger.info(
                "lingua-language-detector not installed; "
                "language routing disabled. "
                "Install with: pip install 'guard-core[prompt_injection]'"
            )
        except Exception as err:
            self._unavailable = True
            logger.error(f"Failed to load lingua language detector: {err}")

    def detect(self, text: str) -> str | None:
        if len(text) < self.min_length:
            return None
        self._load()
        if self._detector is None:
            return None
        try:
            language = self._detector.detect_language_of(text)
        except Exception as err:
            logger.error(f"Language detection failed: {err}")
            return None
        if language is None:
            return None
        return str(language.name).upper()
