<<<<<<< Updated upstream
"""Tests for the optional ML transformer detector.

Since transformers/torch aren't dev dependencies, we test:
- Import fails gracefully when transformers not installed
- Scorer integration with a mocked transformer detector
"""

from unittest.mock import MagicMock

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.prompt_injection.pattern_detector import PatternDetector
from guard_core.sync.prompt_injection.scorer import InjectionScorer
from guard_core.sync.prompt_injection.semantic_analyzer import (
    SemanticAnalyzer,
)
from guard_core.sync.prompt_injection.statistical_detector import (
    StatisticalDetector,
)
from guard_core.sync.prompt_injection.transformer_detector import (
    TransformerDetector,
)


class TestTransformerDetectorNoModel:
    def test_empty_text_returns_zero(self) -> None:
        td = TransformerDetector()
        assert td.get_score("") == 0.0

    def test_not_suspicious_empty(self) -> None:
        td = TransformerDetector()
        assert not td.is_suspicious("")

    def test_load_raises_without_transformers(self) -> None:
        td = TransformerDetector()
        with pytest.raises(ImportError, match="transformers"):
            td._load()

    def test_get_score_raises_without_transformers(self) -> None:
        td = TransformerDetector()
        with pytest.raises(ImportError, match="transformers"):
            td.get_score("test text")


class TestTransformerDetectorLoadMocked:
    def test_load_creates_pipeline(self) -> None:
        """Test the successful load path with mocked import."""
        from unittest.mock import patch

        mock_pipeline_fn = MagicMock()
        mock_pipeline_fn.return_value = "fake_pipeline"

        with patch.dict(
            "sys.modules",
            {"transformers": MagicMock(pipeline=mock_pipeline_fn)},
        ):
            td = TransformerDetector()
            td._load()
            assert td._pipeline == "fake_pipeline"
            mock_pipeline_fn.assert_called_once()

    def test_load_idempotent(self) -> None:
        td = TransformerDetector()
        td._pipeline = "already_loaded"
        td._load()  # Should not reload
        assert td._pipeline == "already_loaded"


class TestTransformerDetectorMocked:
    @pytest.fixture
    def mock_detector(self) -> TransformerDetector:
        td = TransformerDetector(confidence_threshold=0.5)
        mock_pipeline = MagicMock()
        td._pipeline = mock_pipeline
        return td

    def test_injection_detected(self, mock_detector: TransformerDetector) -> None:
        mock_detector._pipeline.return_value = [{"label": "INJECTION", "score": 0.95}]
        assert mock_detector.is_suspicious("ignore instructions")
        assert mock_detector.get_score("ignore instructions") == 0.95

    def test_benign_detected(self, mock_detector: TransformerDetector) -> None:
        mock_detector._pipeline.return_value = [{"label": "SAFE", "score": 0.99}]
        assert not mock_detector.is_suspicious("Hello world")
        score = mock_detector.get_score("Hello world")
        assert score < 0.5

    def test_label_1_format(self, mock_detector: TransformerDetector) -> None:
        mock_detector._pipeline.return_value = [{"label": "LABEL_1", "score": 0.88}]
        assert mock_detector.get_score("test") == 0.88

    def test_label_0_format(self, mock_detector: TransformerDetector) -> None:
        mock_detector._pipeline.return_value = [{"label": "LABEL_0", "score": 0.9}]
        score = mock_detector.get_score("test")
        assert score == pytest.approx(0.1, abs=0.01)

    def test_caching(self, mock_detector: TransformerDetector) -> None:
        mock_detector._pipeline.return_value = [{"label": "INJECTION", "score": 0.8}]
        mock_detector.get_score("cached text")
        mock_detector.get_score("cached text")
        # Pipeline called only once due to cache
        mock_detector._pipeline.assert_called_once()

    def test_prediction_error_returns_zero(
        self, mock_detector: TransformerDetector
    ) -> None:
        mock_detector._pipeline.side_effect = RuntimeError("boom")
        assert mock_detector.get_score("test") == 0.0

    def test_threshold_boundary(self, mock_detector: TransformerDetector) -> None:
        mock_detector.confidence_threshold = 0.9
        mock_detector._pipeline.return_value = [{"label": "INJECTION", "score": 0.85}]
        # 0.85 < 0.9 threshold
        assert not mock_detector.is_suspicious("test")


class TestScorerWithTransformer:
    @pytest.fixture
    def config(self) -> SecurityConfig:
        return SecurityConfig(
            enable_redis=False,
            enable_prompt_injection_detection=True,
        )

    def test_ml_catches_what_patterns_miss(self, config: SecurityConfig) -> None:
        mock_td = MagicMock()
        mock_td.get_score.return_value = 0.95
        mock_td.is_suspicious.return_value = True

        scorer = InjectionScorer(
            pattern_detector=PatternDetector(sensitivity=0.5),
            statistical_detector=StatisticalDetector(),
            semantic_analyzer=SemanticAnalyzer(),
            config=config,
            transformer_detector=mock_td,
        )

        # Text that patterns won't catch
        result = scorer.score("generate c++")
        assert result["is_malicious"]
        assert any("ml_transformer" in p for p in result["matched_patterns"])

    def test_ml_not_called_when_patterns_catch(self, config: SecurityConfig) -> None:
        mock_td = MagicMock()

        scorer = InjectionScorer(
            pattern_detector=PatternDetector(sensitivity=0.5),
            statistical_detector=StatisticalDetector(),
            semantic_analyzer=SemanticAnalyzer(),
            config=config,
            transformer_detector=mock_td,
        )

        # Text that patterns WILL catch
        scorer.score("ignore previous instructions")
        # ML should not be called since patterns caught it
        mock_td.get_score.assert_not_called()

    def test_ml_benign_passes(self, config: SecurityConfig) -> None:
        mock_td = MagicMock()
        mock_td.get_score.return_value = 0.1
        mock_td.is_suspicious.return_value = False

        scorer = InjectionScorer(
            pattern_detector=PatternDetector(sensitivity=0.5),
            statistical_detector=StatisticalDetector(),
            semantic_analyzer=SemanticAnalyzer(),
            config=config,
            transformer_detector=mock_td,
        )

        result = scorer.score("What is the weather?")
        assert not result["is_malicious"]
=======
import logging
from collections.abc import Callable
from typing import Any

import pytest

from guard_core.sync.prompt_injection.transformer_detector import TransformerDetector


class TestNeuterTorchJitScript:
    def test_context_replaces_torch_jit_script_with_identity(self) -> None:
        import torch

        from guard_core.sync.prompt_injection.transformer_detector import (
            _neuter_torch_jit_script,
        )

        def sample() -> int:
            return 42

        original = torch.jit.script
        with _neuter_torch_jit_script():
            result = torch.jit.script(sample)
            assert result is sample
            assert result() == 42
        assert torch.jit.script is original


class TestScoringSchemeValidation:
    def test_multi_label_model_with_softmax_scheme_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import transformers

        class Config:
            problem_type = "multi_label_classification"
            num_labels = 2
            id2label = {0: "prompt_injection", 1: "toxic"}

        class Tokenizer:
            @classmethod
            def from_pretrained(cls, name: str, **_kw: Any) -> "Tokenizer":
                return cls()

        class Model:
            config = Config()

            @classmethod
            def from_pretrained(cls, name: str, **_kw: Any) -> "Model":
                return cls()

            def parameters(self) -> Any:
                import torch

                yield torch.zeros(1)

            def cuda(self) -> "Model":
                return self

        monkeypatch.setattr(transformers, "AutoTokenizer", Tokenizer)
        monkeypatch.setattr(transformers, "AutoModelForSequenceClassification", Model)

        det = TransformerDetector(scoring_scheme="softmax", injection_label_idx=1)
        with pytest.raises(ValueError, match="sigmoid_binary"):
            det._load_model()

    def test_single_label_model_with_sigmoid_scheme_raises(
        self, fake_transformers: None
    ) -> None:
        det = TransformerDetector(
            scoring_scheme="sigmoid_binary", injection_label_idx=0
        )
        with pytest.raises(ValueError, match="softmax"):
            det._load_model()

    def test_out_of_range_injection_label_idx_raises(
        self, fake_transformers: None
    ) -> None:
        det = TransformerDetector(scoring_scheme="softmax", injection_label_idx=5)
        with pytest.raises(ValueError, match="out .+range"):
            det._load_model()

    def test_validation_tolerates_missing_config(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import transformers

        class Tokenizer:
            @classmethod
            def from_pretrained(cls, name: str, **_kw: Any) -> "Tokenizer":
                return cls()

        class Model:
            @classmethod
            def from_pretrained(cls, name: str, **_kw: Any) -> "Model":
                return cls()

            def parameters(self) -> Any:
                import torch

                yield torch.zeros(1)

            def cuda(self) -> "Model":
                return self

        monkeypatch.setattr(transformers, "AutoTokenizer", Tokenizer)
        monkeypatch.setattr(transformers, "AutoModelForSequenceClassification", Model)

        det = TransformerDetector()
        det._load_model()
        assert det._model is not None

    def test_validation_tolerates_missing_problem_type(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import transformers

        class Config:
            num_labels = 2
            id2label = {0: "SAFE", 1: "INJECTION"}

        class Tokenizer:
            @classmethod
            def from_pretrained(cls, name: str, **_kw: Any) -> "Tokenizer":
                return cls()

        class Model:
            config = Config()

            @classmethod
            def from_pretrained(cls, name: str, **_kw: Any) -> "Model":
                return cls()

            def parameters(self) -> Any:
                import torch

                yield torch.zeros(1)

            def cuda(self) -> "Model":
                return self

        monkeypatch.setattr(transformers, "AutoTokenizer", Tokenizer)
        monkeypatch.setattr(transformers, "AutoModelForSequenceClassification", Model)

        det = TransformerDetector()
        det._load_model()
        assert det._model is not None


class TestInitialization:
    def test_defaults(self) -> None:
        det = TransformerDetector()
        assert det.confidence_threshold == 0.5
        assert det.cache_predictions is True
        assert det._model is None

    def test_stats_before_load(self) -> None:
        stats = TransformerDetector().get_stats()
        assert stats["model_loaded"] is False
        assert stats["using_gpu"] is False
        assert stats["cache_size"] == 0


class TestMissingDependencies:
    def test_load_raises_when_transformers_missing(
        self, block_import: Callable[[str], None]
    ) -> None:
        block_import("transformers")
        det = TransformerDetector()
        with pytest.raises(ImportError, match="transformers"):
            det._load_model()

    def test_load_propagates_unexpected_errors(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import transformers

        def raise_download_failed(*_a: Any, **_kw: Any) -> None:
            raise RuntimeError("download failed")

        monkeypatch.setattr(
            transformers.AutoTokenizer,
            "from_pretrained",
            raise_download_failed,
            raising=True,
        )
        monkeypatch.setattr(
            transformers.AutoModelForSequenceClassification,
            "from_pretrained",
            raise_download_failed,
            raising=True,
        )
        det = TransformerDetector()
        with pytest.raises(RuntimeError, match="download failed"):
            det._load_model()

    def test_is_suspicious_returns_false_on_import_error(
        self,
        block_import: Callable[[str], None],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        block_import("transformers")
        det = TransformerDetector()
        with caplog.at_level(logging.ERROR):
            assert det.is_suspicious("anything") is False

    def test_prediction_fallback(
        self,
        block_import: Callable[[str], None],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        block_import("transformers")
        det = TransformerDetector()
        with caplog.at_level(logging.ERROR):
            result = det.get_prediction("anything")
        assert result["is_suspicious"] is False
        assert "error" in result

    def test_batch_predict_fallback(
        self,
        block_import: Callable[[str], None],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        block_import("transformers")
        det = TransformerDetector()
        with caplog.at_level(logging.ERROR):
            results = det.batch_predict(["a", "b"])
        assert len(results) == 2
        assert all(r["is_suspicious"] is False for r in results)


class TestModelLoading:
    def test_load_success(self, fake_transformers: None) -> None:
        det = TransformerDetector()
        det._load_model()
        assert det._model is not None
        assert det._tokenizer is not None

    def test_load_idempotent(self, fake_transformers: None) -> None:
        det = TransformerDetector()
        det._load_model()
        m = det._model
        det._load_model()
        assert det._model is m


class TestCudaPath:
    def test_load_moves_model_to_gpu_when_available(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import torch
        import transformers

        class FakeTokenizer:
            @classmethod
            def from_pretrained(cls, name: str, **_kw: Any) -> "FakeTokenizer":
                return cls()

        model_cuda_called = {"value": False}

        class FakeModel:
            @classmethod
            def from_pretrained(cls, name: str, **_kw: Any) -> "FakeModel":
                return cls()

            def cuda(self) -> "FakeModel":
                model_cuda_called["value"] = True
                return self

            def parameters(self) -> Any:
                yield torch.zeros(1)

        monkeypatch.setattr(transformers, "AutoTokenizer", FakeTokenizer)
        monkeypatch.setattr(
            transformers, "AutoModelForSequenceClassification", FakeModel
        )
        monkeypatch.setattr(torch.cuda, "is_available", lambda: True)

        det = TransformerDetector()
        det._load_model()
        assert model_cuda_called["value"] is True

    def test_predict_moves_inputs_to_cuda(self, fake_transformers_cuda: None) -> None:
        det = TransformerDetector()
        result = det._predict("test")
        assert result["is_injection"] is True

    def test_batch_predict_moves_inputs_to_cuda(
        self, fake_transformers_cuda: None
    ) -> None:
        det = TransformerDetector()
        results = det.batch_predict(["a", "b"])
        assert len(results) == 2


class TestDetection:
    def test_detects_injection(self, fake_transformers: None) -> None:
        det = TransformerDetector(confidence_threshold=0.5)
        assert det.is_suspicious("test") is True

    def test_rejects_below_threshold(self, fake_transformers: None) -> None:
        det = TransformerDetector(confidence_threshold=2.0)
        assert det.is_suspicious("test") is False

    def test_get_prediction_includes_metadata(self, fake_transformers: None) -> None:
        det = TransformerDetector()
        result = det.get_prediction("test")
        assert "is_suspicious" in result
        assert result["model_name"] == det.model_name
        assert result["threshold"] == det.confidence_threshold

    def test_batch_predict(self, fake_transformers: None) -> None:
        det = TransformerDetector()
        results = det.batch_predict(["a", "b", "c"])
        assert len(results) == 3
        assert all(r["is_injection"] is True for r in results)

    def test_batch_predict_sigmoid_binary_reads_configured_index(
        self, fake_transformers_sigmoid: None
    ) -> None:
        det = TransformerDetector(
            scoring_scheme="sigmoid_binary",
            injection_label_idx=0,
            confidence_threshold=0.4,
        )
        results = det.batch_predict(["a", "b"])
        assert len(results) == 2
        for r in results:
            assert 0.0 <= r["injection_score"] <= 1.0
            assert r["is_injection"] == (r["injection_score"] >= 0.4)

    def test_predict_sigmoid_binary_reads_configured_index(
        self, fake_transformers_sigmoid: None
    ) -> None:
        det = TransformerDetector(
            scoring_scheme="sigmoid_binary",
            injection_label_idx=0,
            confidence_threshold=0.4,
        )
        det._load_model()
        result = det._predict_single("a")
        assert 0.0 <= result["injection_score"] <= 1.0
        assert result["benign_score"] == 1.0 - result["injection_score"]
        assert result["is_injection"] == (result["injection_score"] >= 0.4)


class TestPredictionCache:
    def test_cache_hit(self, fake_transformers: None) -> None:
        det = TransformerDetector(cache_predictions=True)
        r1 = det._predict("xyz")
        r2 = det._predict("xyz")
        assert r1 is r2

    def test_cache_disabled(self, fake_transformers: None) -> None:
        det = TransformerDetector(cache_predictions=False)
        det._predict("xyz")
        assert "xyz" not in det._prediction_cache

    def test_clear_cache(self, fake_transformers: None) -> None:
        det = TransformerDetector()
        det._predict("xyz")
        assert det._prediction_cache
        det.clear_cache()
        assert not det._prediction_cache


class TestErrorPaths:
    def test_predict_propagates_inference_errors(
        self,
        fake_transformers: None,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        det = TransformerDetector()
        det._load_model()

        def boom(self: Any, **_kw: Any) -> Any:
            raise RuntimeError("inference failure")

        monkeypatch.setattr(det._model.__class__, "__call__", boom, raising=True)
        with caplog.at_level(logging.ERROR):
            with pytest.raises(RuntimeError, match="inference failure"):
                det._predict("x")

    def test_batch_predict_recovers_from_inference_errors(
        self,
        fake_transformers: None,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        det = TransformerDetector()
        det._load_model()

        def boom(self: Any, **_kw: Any) -> Any:
            raise RuntimeError("batch failure")

        monkeypatch.setattr(det._model.__class__, "__call__", boom, raising=True)
        with caplog.at_level(logging.ERROR):
            results = det.batch_predict(["a"])
        assert len(results) == 1
        assert results[0]["is_suspicious"] is False


class TestStats:
    def test_stats_after_load(self, fake_transformers: None) -> None:
        det = TransformerDetector()
        det._load_model()
        stats = det.get_stats()
        assert stats["model_loaded"] is True

    def test_stats_tolerates_parameters_error(
        self, fake_transformers: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        det = TransformerDetector()
        det._load_model()

        def broken_parameters(self: Any) -> Any:
            raise RuntimeError("no params")

        monkeypatch.setattr(
            det._model.__class__, "parameters", broken_parameters, raising=True
        )
        stats = det.get_stats()
        assert stats["using_gpu"] is False


class TestLongInputWindowing:
    def test_short_input_takes_single_path(
        self, fake_long_input_transformers: list[list[float]]
    ) -> None:
        det = TransformerDetector(window_size=512)
        det._load_model()
        windows = det._split_text_into_token_windows("short")
        assert windows == ["short"]

    def test_long_input_splits_into_multiple_windows(
        self, fake_long_input_transformers: list[list[float]]
    ) -> None:
        det = TransformerDetector(window_size=100, window_overlap=10)
        det._load_model()
        text = "x" * 350
        windows = det._split_text_into_token_windows(text)
        assert len(windows) > 1
        assert all(isinstance(w, str) for w in windows)

    def test_aggregation_max_picks_highest_score(
        self, fake_long_input_transformers: list[list[float]]
    ) -> None:
        det = TransformerDetector(long_input_strategy="max")
        per_window = [
            {"injection_score": 0.1, "is_injection": False},
            {"injection_score": 0.9, "is_injection": True},
            {"injection_score": 0.2, "is_injection": False},
        ]
        result = det._aggregate_window_predictions(per_window)
        assert result["injection_score"] == pytest.approx(0.9)
        assert result["is_injection"] is True
        assert result["aggregation"] == "max"
        assert result["windows"] == 3

    def test_aggregation_mean_averages(
        self, fake_long_input_transformers: list[list[float]]
    ) -> None:
        det = TransformerDetector(long_input_strategy="mean", confidence_threshold=0.5)
        per_window = [
            {"injection_score": 0.2, "is_injection": False},
            {"injection_score": 0.2, "is_injection": False},
        ]
        result = det._aggregate_window_predictions(per_window)
        assert result["injection_score"] == pytest.approx(0.2)
        assert result["is_injection"] is False

    def test_aggregation_any_fires_on_single_window(
        self, fake_long_input_transformers: list[list[float]]
    ) -> None:
        det = TransformerDetector(long_input_strategy="any", confidence_threshold=0.5)
        per_window = [
            {"injection_score": 0.1, "is_injection": False},
            {"injection_score": 0.6, "is_injection": True},
            {"injection_score": 0.1, "is_injection": False},
        ]
        result = det._aggregate_window_predictions(per_window)
        assert result["is_injection"] is True
        assert result["aggregation"] == "any"

    def test_catches_injection_after_benign_prefix(
        self, fake_long_input_transformers: list[list[float]]
    ) -> None:
        fake_long_input_transformers.extend(
            [
                [3.0, 1.0],
                [3.0, 1.0],
                [1.0, 3.0],
            ]
        )

        det = TransformerDetector(
            window_size=100,
            window_overlap=10,
            confidence_threshold=0.5,
            long_input_strategy="max",
            cache_predictions=False,
        )
        result = det._predict("x" * 350)
        assert result["is_injection"] is True
        assert result["windows"] >= 2
>>>>>>> Stashed changes
