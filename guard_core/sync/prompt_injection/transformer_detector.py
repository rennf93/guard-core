<<<<<<< Updated upstream
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
=======
import contextlib
import logging
from collections.abc import Iterator
from typing import Any, Literal

logger = logging.getLogger(__name__)

LongInputStrategy = Literal["max", "mean", "any"]
ScoringScheme = Literal["softmax", "sigmoid_binary"]


@contextlib.contextmanager
def _neuter_torch_jit_script() -> Iterator[None]:
    """Replace torch.jit.script with identity during model import.

    Several HuggingFace modeling modules (notably DeBERTa-v2, which backs our
    default multilingual model) apply @torch.jit.script at module load time.
    torch ≥ 2.10 deprecates that API and emits a DeprecationWarning once per
    decorated function. transformers has not migrated. JIT compilation is an
    optional optimization, not a correctness requirement; the forward pass is
    identical with a plain-Python callable. We swap torch.jit.script for an
    identity pass-through for the duration of from_pretrained so the warning
    never fires. Remove this shim once upstream migrates to torch.compile /
    torch.export.
    """
    import torch

    def identity(fn: Any = None, *_a: Any, **_kw: Any) -> Any:
        return fn

    jit_module: Any = torch.jit
    original = jit_module.script
    jit_module.script = identity
    try:
        yield
    finally:
        jit_module.script = original


class TransformerDetector:
    """
    Transformer-based classifier for prompt-injection detection.

    Wraps a HuggingFace sequence-classification model that emits an
    INJECTION vs SAFE probability. Results depend strongly on the model
    chosen and the language / phrasing of the input — see
    `benchmarks/prompt_injection/results/calibration.json` for measured
    recall / precision / FPR on the eval_v1 test split. Do not rely on the
    accuracy numbers published in a model's upstream README without
    re-measuring against your own traffic.
>>>>>>> Stashed changes
    """

    def __init__(
        self,
<<<<<<< Updated upstream
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
=======
        model_name: str = "protectai/deberta-v3-base-prompt-injection",
        confidence_threshold: float = 0.5,
        cache_predictions: bool = True,
        model_revision: str = "main",
        window_size: int = 512,
        window_overlap: int = 64,
        long_input_strategy: LongInputStrategy = "max",
        scoring_scheme: ScoringScheme = "softmax",
        injection_label_idx: int = 1,
    ) -> None:
        """
        Initialize the transformer detector.

        Args:
            model_name: HuggingFace model name for detection. Any sequence
                classifier that outputs {SAFE, INJECTION} (in either label
                order) works; calibrate the threshold per model.
            confidence_threshold: Confidence threshold (0.0-1.0) applied to
                the INJECTION class probability. The default 0.5 is a
                placeholder; use the calibrated value from
                `benchmarks/prompt_injection/results/calibration.json`.
            cache_predictions: Whether to cache predictions.
            model_revision: Git revision (commit SHA, tag, or branch)
                to pin the downloaded model weights. Default "main".
            window_size: Max tokens per prediction window. Inputs longer
                than this are split into overlapping windows so that
                injection payloads hidden after a long benign prefix are
                not silently truncated.
            window_overlap: Tokens shared between consecutive windows so
                that a payload spanning a window boundary is seen whole
                by at least one classification.
            long_input_strategy: How per-window scores are combined.
                "max" (default): the most suspicious window wins — safest
                for detection. "mean": average across windows — more
                conservative, likely to under-detect short payloads in
                long benign text. "any": fires if any window is above
                `confidence_threshold` — equivalent to "max" with a hard
                threshold.
        """
        self.model_name = model_name
        self.model_revision = model_revision
        self.confidence_threshold = confidence_threshold
        self.cache_predictions = cache_predictions
        self.window_size = window_size
        self.window_overlap = window_overlap
        self.long_input_strategy: LongInputStrategy = long_input_strategy
        self.scoring_scheme: ScoringScheme = scoring_scheme
        self.injection_label_idx = injection_label_idx

        self._model: Any = None
        self._tokenizer: Any = None
        self._prediction_cache: dict[str, dict[str, Any]] = {}

        logger.info(
            "TransformerDetector initialized with "
            f"model={model_name}@{model_revision}, "
            f"threshold={confidence_threshold}"
        )

    def _load_model(self) -> None:
        """Load the transformer model and tokenizer lazily."""
        if self._model is not None:
            return

        try:
            with _neuter_torch_jit_script():
                from transformers import (
                    AutoModelForSequenceClassification,
                    AutoTokenizer,
                )

                logger.info(f"Loading transformer model: {self.model_name}")

                self._tokenizer = AutoTokenizer.from_pretrained(
                    self.model_name, revision=self.model_revision
                )
                self._model = AutoModelForSequenceClassification.from_pretrained(
                    self.model_name, revision=self.model_revision
                )

            import torch

            if torch.cuda.is_available():
                self._model = self._model.cuda()
                logger.info("Model moved to GPU")

            self._validate_scoring_scheme()
            logger.info("Model loaded successfully")

        except ImportError as e:
            logger.error(
                "transformers not installed. "
                "Install with: pip install 'guard-core[prompt_injection]'"
            )
            raise ImportError(
                "TransformerDetector requires transformers. "
                "Install with: pip install 'guard-core[prompt_injection]'"
            ) from e
        except Exception as e:
            logger.error(f"Failed to load model {self.model_name}: {e}")
            raise

    def _validate_scoring_scheme(self) -> None:
        """Fail loud if scoring_scheme disagrees with the loaded model's head.

        Reads `problem_type` and `num_labels` from the model config. A
        DeBERTa-style binary softmax classifier reports
        `problem_type="single_label_classification"` with `num_labels=2`. A
        multi-label sigmoid model (e.g. mmBERT-v3.5) reports
        `problem_type="multi_label_classification"`. When these disagree with
        the configured `scoring_scheme`, inference is silently wrong — the
        prediction path softmax-normalises independent per-label logits into
        a bogus distribution, or vice versa. Raise early with a message that
        tells the user which config fields to change.
        """
        config = getattr(self._model, "config", None)
        if config is None:
            return
        problem_type = getattr(config, "problem_type", None)
        num_labels = getattr(config, "num_labels", None)

        if (
            problem_type == "multi_label_classification"
            and self.scoring_scheme != "sigmoid_binary"
        ):
            raise ValueError(
                f"Model {self.model_name!r} has problem_type="
                f"{problem_type!r} (multi-label sigmoid head) but "
                f"scoring_scheme={self.scoring_scheme!r}. Set "
                "scoring_scheme='sigmoid_binary' and configure "
                "injection_label_idx to match the model's id2label "
                f"mapping: {getattr(config, 'id2label', None)!r}"
            )
        if (
            problem_type == "single_label_classification"
            and self.scoring_scheme != "softmax"
        ):
            raise ValueError(
                f"Model {self.model_name!r} has problem_type="
                f"{problem_type!r} (single-label softmax head) but "
                f"scoring_scheme={self.scoring_scheme!r}. Set "
                "scoring_scheme='softmax' and configure "
                "injection_label_idx to match the model's id2label "
                f"mapping: {getattr(config, 'id2label', None)!r}"
            )
        if num_labels is not None and self.injection_label_idx >= num_labels:
            raise ValueError(
                f"injection_label_idx={self.injection_label_idx} is out "
                f"of range for model {self.model_name!r} which has "
                f"num_labels={num_labels}. id2label="
                f"{getattr(config, 'id2label', None)!r}"
            )

    def _predict(self, text: str) -> dict[str, Any]:
        """
        Run model prediction on text, splitting long inputs into windows.

        Args:
            text: Input text to analyze.

        Returns:
            Prediction dictionary with scores and labels.
        """
        if self.cache_predictions and text in self._prediction_cache:
            return self._prediction_cache[text]

        self._load_model()

        try:
            windows = self._split_text_into_token_windows(text)
            if len(windows) == 1:
                result = self._predict_single(text)
            else:
                per_window = [self._predict_single(w) for w in windows]
                result = self._aggregate_window_predictions(per_window)

            if self.cache_predictions:
                self._prediction_cache[text] = result

            return result

        except Exception as e:
            logger.error(f"Error during prediction: {e}")
            raise

    def _predict_single(self, text: str) -> dict[str, Any]:
        import torch

        inputs = self._tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=self.window_size,
            padding=True,
        )

        if next(self._model.parameters()).is_cuda:
            inputs = {k: v.cuda() for k, v in inputs.items()}

        with torch.no_grad():
            outputs = self._model(**inputs)
            logits = outputs.logits
            if self.scoring_scheme == "sigmoid_binary":
                probabilities = torch.sigmoid(logits)
            else:
                probabilities = torch.softmax(logits, dim=-1)

        idx = self.injection_label_idx
        injection_confidence = probabilities[0][idx].item()
        benign_confidence = 1.0 - injection_confidence
        is_injection = injection_confidence >= self.confidence_threshold
        confidence = max(injection_confidence, benign_confidence)

        return {
            "is_injection": bool(is_injection),
            "confidence": float(confidence),
            "injection_score": float(injection_confidence),
            "benign_score": float(benign_confidence),
            "predicted_class": 1 if is_injection else 0,
        }

    def _split_text_into_token_windows(self, text: str) -> list[str]:
        encoding = self._tokenizer(
            text,
            truncation=False,
            add_special_tokens=False,
        )
        input_ids = encoding["input_ids"]
        total = len(input_ids)

        if total <= self.window_size:
            return [text]

        step = max(1, self.window_size - self.window_overlap)
        positions: list[int] = []
        start = 0
        while start + self.window_size < total:
            positions.append(start)
            start += step
        positions.append(start)

        return [
            self._tokenizer.decode(
                input_ids[p : min(p + self.window_size, total)],
                skip_special_tokens=True,
            )
            for p in positions
        ]

    def _aggregate_window_predictions(
        self, predictions: list[dict[str, Any]]
    ) -> dict[str, Any]:
        scores = [p["injection_score"] for p in predictions]
        strategy = self.long_input_strategy
        if strategy == "mean":
            aggregated = sum(scores) / len(scores)
        else:
            aggregated = max(scores)

        if strategy == "any":
            is_injection = any(s >= self.confidence_threshold for s in scores)
        else:
            is_injection = aggregated >= self.confidence_threshold

        return {
            "is_injection": bool(is_injection),
            "confidence": float(aggregated),
            "injection_score": float(aggregated),
            "benign_score": float(1.0 - aggregated),
            "predicted_class": 1 if is_injection else 0,
            "windows": len(predictions),
            "window_scores": [float(s) for s in scores],
            "aggregation": strategy,
        }

    def is_suspicious(self, text: str) -> bool:
        """
        Check if text is a prompt injection attempt.

        Args:
            text: Input text to analyze.

        Returns:
            True if injection detected, False otherwise.
        """
        try:
            prediction = self._predict(text)

            is_suspicious = bool(
                prediction["is_injection"]
                and prediction["injection_score"] >= self.confidence_threshold
            )

            if is_suspicious:
                logger.warning(
                    f"Injection detected (confidence: "
                    f"{prediction['injection_score']:.3f})"
                )

            return is_suspicious

        except Exception as e:
            logger.error(f"Error in transformer detection: {e}")
            return False

    def get_prediction(self, text: str) -> dict[str, Any]:
        """
        Get detailed prediction analysis.

        Args:
            text: Input text to analyze.

        Returns:
            Dictionary with prediction details.
        """
        try:
            prediction = self._predict(text)

            prediction["is_suspicious"] = (
                prediction["is_injection"]
                and prediction["injection_score"] >= self.confidence_threshold
            )
            prediction["threshold"] = self.confidence_threshold
            prediction["model_name"] = self.model_name

            return prediction

        except Exception as e:
            logger.error(f"Error getting prediction: {e}")
            return {
                "is_suspicious": False,
                "is_injection": False,
                "confidence": 0.0,
                "injection_score": 0.0,
                "benign_score": 0.0,
                "threshold": self.confidence_threshold,
                "error": str(e),
            }

    def batch_predict(self, texts: list[str]) -> list[dict[str, Any]]:
        try:
            self._load_model()
            import torch

            inputs = self._tokenizer(
                texts,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True,
            )

            if next(self._model.parameters()).is_cuda:
                inputs = {k: v.cuda() for k, v in inputs.items()}

            with torch.no_grad():
                outputs = self._model(**inputs)
                logits = outputs.logits
                if self.scoring_scheme == "sigmoid_binary":
                    probabilities = torch.sigmoid(logits)
                else:
                    probabilities = torch.softmax(logits, dim=-1)

            idx = self.injection_label_idx
            results = []
            for i in range(len(texts)):
                injection_confidence = probabilities[i][idx].item()
                benign_confidence = 1.0 - injection_confidence
                is_injection = injection_confidence >= self.confidence_threshold
                confidence = max(injection_confidence, benign_confidence)

                results.append(
                    {
                        "is_injection": bool(is_injection),
                        "confidence": float(confidence),
                        "injection_score": float(injection_confidence),
                        "benign_score": float(benign_confidence),
                        "predicted_class": 1 if is_injection else 0,
                        "is_suspicious": is_injection,
                    }
                )

            return results

        except Exception as e:
            logger.error(f"Error in batch prediction: {e}")
            return [{"is_suspicious": False, "error": str(e)} for _ in texts]

    def clear_cache(self) -> None:
        """Clear the prediction cache."""
        self._prediction_cache.clear()
        logger.info("Prediction cache cleared")

    def get_stats(self) -> dict[str, Any]:
        """
        Get detector statistics.

        Returns:
            Dictionary with detector stats.
        """
        is_cuda = False
        if self._model is not None:
            try:
                is_cuda = next(self._model.parameters()).is_cuda
            except Exception:
                pass

        return {
            "model_name": self.model_name,
            "model_loaded": self._model is not None,
            "confidence_threshold": self.confidence_threshold,
            "cache_size": len(self._prediction_cache),
            "cache_enabled": self.cache_predictions,
            "using_gpu": is_cuda,
        }
>>>>>>> Stashed changes
