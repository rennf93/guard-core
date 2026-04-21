from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dataset_loaders import Sample


@dataclass
class ConfusionMatrix:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    fn_samples: list[str] = field(default_factory=list)
    fp_samples: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 0.0

    @property
    def fpr(self) -> float:
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    def to_dict(self) -> dict:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "total": self.total,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "fpr": round(self.fpr, 4),
            "fn_samples": self.fn_samples[:10],
            "fp_samples": self.fp_samples[:10],
        }


def evaluate(
    samples: Iterable[tuple[str, bool]],
    classifier: Callable[[str], bool],
) -> ConfusionMatrix:
    cm = ConfusionMatrix()
    for text, is_malicious in samples:
        predicted = classifier(text)
        if is_malicious and predicted:
            cm.tp += 1
        elif is_malicious and not predicted:
            cm.fn += 1
            if len(cm.fn_samples) < 50:
                cm.fn_samples.append(text[:200])
        elif not is_malicious and predicted:
            cm.fp += 1
            if len(cm.fp_samples) < 50:
                cm.fp_samples.append(text[:200])
        else:
            cm.tn += 1
    return cm


def evaluate_by_language(
    samples: "Iterable[Sample]",
    classifier: Callable[[str], bool],
) -> dict[str, ConfusionMatrix]:
    """Return one ConfusionMatrix per language, plus an 'all' aggregate."""
    per_lang: dict[str, ConfusionMatrix] = {"all": ConfusionMatrix()}
    for s in samples:
        predicted = classifier(s.text)
        cms = [per_lang["all"], per_lang.setdefault(s.language, ConfusionMatrix())]
        for cm in cms:
            if s.label and predicted:
                cm.tp += 1
            elif s.label and not predicted:
                cm.fn += 1
                if len(cm.fn_samples) < 50:
                    cm.fn_samples.append(s.text[:200])
            elif not s.label and predicted:
                cm.fp += 1
                if len(cm.fp_samples) < 50:
                    cm.fp_samples.append(s.text[:200])
            else:
                cm.tn += 1
    return per_lang


def load_split(
    split: str,
    manifest_path: Path | None = None,
    jayavibhav_max: int | None = 20_000,
) -> "list[Sample]":
    """Resolve `split` ('train'/'val'/'test') via the manifest and loaders."""
    from dataset_loaders import apply_manifest, load_all, read_manifest

    if manifest_path is None:
        manifest_path = Path(__file__).parent / "manifests" / "eval_v1.json"
    manifest_ids = read_manifest(manifest_path)
    all_samples = load_all(jayavibhav_max=jayavibhav_max)
    assigned = apply_manifest(all_samples, manifest_ids)
    if split not in assigned:
        raise KeyError(f"split {split!r} not found in manifest")
    return assigned[split]


def pattern_only_classifier() -> Callable[[str], bool]:
    from guard_core.prompt_injection import PatternDetector

    detector = PatternDetector(sensitivity=0.0)

    def classify(text: str) -> bool:
        return detector.is_suspicious(text)

    return classify


def scorer_classifier(
    enable_statistical_boost: bool = True,
    detection_threshold: float = 0.7,
) -> Callable[[str], bool]:
    from guard_core.detection_engine.semantic import SemanticAnalyzer
    from guard_core.prompt_injection import PatternDetector
    from guard_core.prompt_injection.scorer import InjectionScorer

    scorer = InjectionScorer(
        pattern_detector=PatternDetector(sensitivity=0.0),
        semantic_analyzer=SemanticAnalyzer() if enable_statistical_boost else None,
        detection_threshold=detection_threshold,
        enable_statistical_boost=enable_statistical_boost,
    )

    def classify(text: str) -> bool:
        return scorer.is_malicious(text)

    return classify


def embedding_classifier(
    similarity_threshold: float = 0.5,
    model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
) -> Callable[[str], bool]:
    """Embedding-only classifier. Requires guard-core[prompt_injection]."""
    from guard_core.prompt_injection import EmbeddingDetector

    detector = EmbeddingDetector(
        model_name=model_name,
        similarity_threshold=similarity_threshold,
    )
    detector._load_model()

    def classify(text: str) -> bool:
        return detector.is_suspicious(text)

    return classify


def transformer_classifier(
    confidence_threshold: float = 0.5,
    model_name: str = "protectai/deberta-v3-base-prompt-injection",
    model_revision: str = "main",
) -> Callable[[str], bool]:
    """Transformer-only classifier. Requires guard-core[prompt_injection]."""
    from guard_core.prompt_injection import TransformerDetector

    detector = TransformerDetector(
        model_name=model_name,
        confidence_threshold=confidence_threshold,
        model_revision=model_revision,
    )
    detector._load_model()

    def classify(text: str) -> bool:
        return detector.is_suspicious(text)

    return classify


def full_stack_classifier(
    detection_threshold: float = 0.7,
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2",
    transformer_model: str = "protectai/deberta-v3-base-prompt-injection",
    transformer_revision: str = "main",
) -> Callable[[str], bool]:
    """Pattern + statistical + embedding + transformer cascade via PromptGuard.

    Requires guard-core[prompt_injection]. Models are loaded once up front so
    the benchmark timing reflects steady-state classification cost.
    """
    from guard_core.prompt_injection import PromptGuard, PromptInjectionAttempt

    guard = PromptGuard(
        protection_level="enabled",
        enable_canary=False,
        enable_statistical_boost=True,
        enable_embedding_detection=True,
        enable_transformer_detection=True,
        embedding_model=embedding_model,
        transformer_model=transformer_model,
        transformer_revision=transformer_revision,
        detection_threshold=detection_threshold,
    )
    if guard.embedding_detector is not None:
        guard.embedding_detector._load_model()
    if guard.transformer_detector is not None:
        guard.transformer_detector._load_model()

    def classify(text: str) -> bool:
        try:
            guard.protect_input(text, session_id=None)
        except PromptInjectionAttempt:
            return True
        return False

    return classify
