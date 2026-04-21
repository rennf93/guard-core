import builtins
import logging
import sys
from typing import Any

import numpy as np
import pytest

from guard_core.prompt_injection.embedding_detector import EmbeddingDetector


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
def fake_sentence_transformer(monkeypatch: pytest.MonkeyPatch) -> None:
    import sentence_transformers

    class FakeST:
        def __init__(self, name: str) -> None:
            self.name = name

        def encode(self, texts: list[str], convert_to_numpy: bool = True) -> np.ndarray:
            return np.array([[1.0, 0.0, 0.0] for _ in texts])

    monkeypatch.setattr(
        sentence_transformers, "SentenceTransformer", FakeST, raising=True
    )


class TestInitialization:
    def test_defaults(self) -> None:
        det = EmbeddingDetector()
        assert det.model_name.startswith("sentence-transformers/")
        assert det.similarity_threshold == 0.5
        assert det.cache_embeddings is True
        assert det._model is None
        assert len(det._attack_patterns) > 0

    def test_stats_before_load(self) -> None:
        stats = EmbeddingDetector().get_stats()
        assert stats["model_loaded"] is False
        assert stats["cache_size"] == 0
        assert stats["attack_patterns"] > 0


class TestMissingDependencies:
    def test_load_raises_when_sentence_transformers_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _block_import(monkeypatch, "sentence_transformers")
        det = EmbeddingDetector()
        with pytest.raises(ImportError, match="sentence-transformers"):
            det._load_model()

    def test_load_propagates_unexpected_errors(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import sentence_transformers

        class BrokenModel:
            def __init__(self, name: str) -> None:
                raise RuntimeError("boom")

        monkeypatch.setattr(
            sentence_transformers, "SentenceTransformer", BrokenModel, raising=True
        )
        det = EmbeddingDetector()
        with pytest.raises(RuntimeError, match="boom"):
            det._load_model()

    def test_is_suspicious_returns_false_on_import_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        _block_import(monkeypatch, "sentence_transformers")
        det = EmbeddingDetector()
        with caplog.at_level(logging.ERROR):
            assert det.is_suspicious("anything") is False

    def test_similarity_score_fallback_on_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        _block_import(monkeypatch, "sentence_transformers")
        det = EmbeddingDetector()
        with caplog.at_level(logging.ERROR):
            result = det.get_similarity_score("anything")
        assert result["is_suspicious"] is False
        assert result["max_similarity"] == 0.0
        assert "error" in result


class TestModelLoading:
    def test_load_success(self, fake_sentence_transformer: None) -> None:
        det = EmbeddingDetector()
        det._load_model()
        assert det._model is not None
        assert det._attack_embeddings is not None

    def test_load_idempotent(self, fake_sentence_transformer: None) -> None:
        det = EmbeddingDetector()
        det._load_model()
        m = det._model
        det._load_model()
        assert det._model is m


class TestDetection:
    def test_detects_similar_input(self, fake_sentence_transformer: None) -> None:
        det = EmbeddingDetector(similarity_threshold=0.5)
        assert det.is_suspicious("hello") is True

    def test_rejects_dissimilar_input(self, fake_sentence_transformer: None) -> None:
        det = EmbeddingDetector(similarity_threshold=2.0)
        assert det.is_suspicious("hello") is False

    def test_similarity_score_breakdown(self, fake_sentence_transformer: None) -> None:
        det = EmbeddingDetector(similarity_threshold=0.5)
        result = det.get_similarity_score("hi")
        assert result["is_suspicious"] is True
        assert result["max_similarity"] == pytest.approx(1.0)
        assert len(result["top_matches"]) == 5
        assert result["total_patterns"] > 0


class TestEmbeddingCache:
    def test_cache_hit_returns_same_object(
        self, fake_sentence_transformer: None
    ) -> None:
        det = EmbeddingDetector(cache_embeddings=True)
        det._load_model()
        e1 = det._get_embedding("abc")
        e2 = det._get_embedding("abc")
        assert e1 is e2

    def test_cache_disabled_stores_nothing(
        self, fake_sentence_transformer: None
    ) -> None:
        det = EmbeddingDetector(cache_embeddings=False)
        det._load_model()
        det._get_embedding("abc")
        assert "abc" not in det._embedding_cache

    def test_clear_cache(self, fake_sentence_transformer: None) -> None:
        det = EmbeddingDetector()
        det._load_model()
        det._get_embedding("abc")
        assert len(det._embedding_cache) > 0
        det.clear_cache()
        assert len(det._embedding_cache) == 0


class TestAttackPatternManagement:
    def test_add_recomputes_embeddings(self, fake_sentence_transformer: None) -> None:
        det = EmbeddingDetector()
        det._load_model()
        before = len(det._attack_patterns)
        det.add_attack_pattern("a novel attack")
        assert len(det._attack_patterns) == before + 1
        det.add_attack_pattern("a novel attack")
        assert len(det._attack_patterns) == before + 1

    def test_add_before_load_defers_encoding(self) -> None:
        det = EmbeddingDetector()
        before = len(det._attack_patterns)
        det.add_attack_pattern("novel attack")
        assert len(det._attack_patterns) == before + 1


class TestCosineSimilarity:
    def test_zero_vector_returns_zero(self) -> None:
        det = EmbeddingDetector()
        zero = np.zeros(3)
        v = np.array([1.0, 0.0, 0.0])
        assert det._cosine_similarity(zero, v) == 0.0
        assert det._cosine_similarity(v, zero) == 0.0

    def test_parallel_vectors(self) -> None:
        det = EmbeddingDetector()
        v = np.array([1.0, 2.0, 3.0])
        assert det._cosine_similarity(v, v) == pytest.approx(1.0)

    def test_orthogonal_vectors(self) -> None:
        det = EmbeddingDetector()
        a = np.array([1.0, 0.0, 0.0])
        b = np.array([0.0, 1.0, 0.0])
        assert det._cosine_similarity(a, b) == pytest.approx(0.0)


class TestLongInputWindowing:
    def test_short_input_single_window(self) -> None:
        det = EmbeddingDetector(window_chars=100)
        assert det._split_text_into_char_windows("abc") == ["abc"]

    def test_long_input_splits_with_overlap(self) -> None:
        det = EmbeddingDetector(window_chars=10, window_overlap_chars=2)
        text = "x" * 30
        windows = det._split_text_into_char_windows(text)
        assert len(windows) >= 3
        assert all(len(w) <= 10 for w in windows)

    def test_aggregate_max_picks_highest(self) -> None:
        det = EmbeddingDetector(long_input_strategy="max")
        per_window = [
            {"similarity": 0.1, "index": 0},
            {"similarity": 0.8, "index": 1},
            {"similarity": 0.2, "index": 0},
        ]
        assert det._aggregate_window_similarity(per_window) == pytest.approx(0.8)

    def test_aggregate_mean_averages(self) -> None:
        det = EmbeddingDetector(long_input_strategy="mean")
        per_window = [
            {"similarity": 0.2, "index": 0},
            {"similarity": 0.4, "index": 1},
        ]
        assert det._aggregate_window_similarity(per_window) == pytest.approx(0.3)

    def test_any_strategy_fires_on_single_window(self) -> None:
        det = EmbeddingDetector(long_input_strategy="any", similarity_threshold=0.5)
        per_window = [
            {"similarity": 0.1, "index": 0},
            {"similarity": 0.7, "index": 1},
        ]
        assert det._is_window_suspicious(per_window) is True

    def test_long_input_catches_payload_in_final_window(self) -> None:
        class BenignThenAttackST:
            def __init__(self, name: str) -> None:
                self.name = name

            def encode(
                self, texts: list[str], convert_to_numpy: bool = True
            ) -> np.ndarray:
                result = []
                for text in texts:
                    if "ATTACK" in text:
                        result.append(np.array([1.0, 0.0, 0.0]))
                    else:
                        result.append(np.array([0.0, 1.0, 0.0]))
                return np.array(result)

        det = EmbeddingDetector(
            window_chars=20,
            window_overlap_chars=2,
            similarity_threshold=0.9,
            long_input_strategy="max",
            cache_embeddings=False,
        )
        det._model = BenignThenAttackST(det.model_name)
        det._attack_embeddings = np.array([[1.0, 0.0, 0.0]])

        text = "benign text goes here " * 5 + "PAYLOAD ATTACK"
        assert det.is_suspicious(text) is True

    def test_get_similarity_score_reports_windows(
        self, fake_sentence_transformer: None
    ) -> None:
        det = EmbeddingDetector(
            window_chars=20,
            window_overlap_chars=2,
            long_input_strategy="max",
            cache_embeddings=False,
        )
        det._load_model()
        result = det.get_similarity_score("x" * 60)
        assert "windows" in result
        assert result["windows"] >= 2
        assert len(result["per_window"]) == result["windows"]
        assert "aggregation" in result
        assert "closest_attack" in result
