"""
Optional ML-based prompt injection detection using transformer models.

Requires: pip install transformers torch
Uses ProtectAI's DeBERTa model (99%+ accuracy on prompt injection).
Lazy-loads the model on first use (~500MB download on first run).
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)


class TransformerDetector:
    """
    High-accuracy detection using pre-trained DeBERTa model.

    Optional — requires `transformers` and `torch`.
    Lazy-loads model on first call. Caches predictions.
    """

    def __init__(
        self,
        model_name: str = "protectai/deberta-v3-base-prompt-injection-v2",
        confidence_threshold: float = 0.5,
    ) -> None:
        self.model_name = model_name
        self.confidence_threshold = confidence_threshold
        self._pipeline: Any = None
        self._cache: dict[str, float] = {}

    def _load(self) -> None:
        if self._pipeline is not None:
            return

        try:
            from transformers import pipeline  # type: ignore[import-not-found]
        except ImportError as e:
            raise ImportError(
                "TransformerDetector requires 'transformers' and 'torch'. "
                "Install with: pip install transformers torch"
            ) from e

        logger.info(f"Loading model: {self.model_name}")
        self._pipeline = pipeline(
            "text-classification",
            model=self.model_name,
            truncation=True,
            max_length=512,
        )
        logger.info("Model loaded")

    def get_score(self, text: str) -> float:
        """
        Get injection probability score (0-1).

        Returns the model's confidence that the text is an injection.
        """
        if not text:
            return 0.0

        if text in self._cache:
            return self._cache[text]

        self._load()

        try:
            result = self._pipeline(text)[0]
            # Model outputs: LABEL_0=benign, LABEL_1=injection
            # (or SAFE/INJECTION depending on model version)
            label = result["label"].upper()
            score_val = float(result["score"])

            if label in ("INJECTION", "LABEL_1"):
                injection_score = score_val
            else:
                injection_score = 1.0 - score_val

            self._cache[text] = injection_score
            return injection_score

        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return 0.0

    def is_suspicious(self, text: str) -> bool:
        """Check if text is a prompt injection attempt."""
        return self.get_score(text) >= self.confidence_threshold
