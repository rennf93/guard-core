<<<<<<< Updated upstream
from __future__ import annotations

from typing import TYPE_CHECKING, TypedDict

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig
    from guard_core.prompt_injection.pattern_detector import (
        PatternDetector,
    )
    from guard_core.prompt_injection.semantic_analyzer import (
        SemanticAnalyzer,
    )
    from guard_core.prompt_injection.statistical_detector import (
        StatisticalDetector,
    )
    from guard_core.prompt_injection.transformer_detector import (
        TransformerDetector,
    )


class InjectionScore(TypedDict):
    """Complete injection detection score."""

    total_score: float
    pattern_score: float
    statistical_score: float
    is_malicious: bool
    matched_patterns: list[str]
=======
from typing import TypedDict

from guard_core.detection_engine.semantic import SemanticAnalyzer
from guard_core.prompt_injection.context_detector import (
    ContextAwareDetector,
    ContextType,
)
from guard_core.prompt_injection.pattern_detector import PatternDetector


class ScoreComponents(TypedDict):
    patterns: float
    statistical: float
    context: float


class InjectionScore(TypedDict, total=False):
    total_score: float
    components: ScoreComponents
    threshold: float
    is_malicious: bool
    confidence: float
    matched_patterns: list[str]
    pattern_score: float
    statistical_score: float
    context_score: float
    cascade_stopped_at: str
    layers_skipped: list[str]
>>>>>>> Stashed changes


class InjectionScorer:
    """
<<<<<<< Updated upstream
    Score injection probability using multiple detection layers.

    Layer 1: Pattern matching on raw text (fast, primary signal)
    Layer 2: Semantic analysis on normalized text (synonym/homoglyph)
    Layer 3: Pattern matching on normalized text (post-normalization)
    Layer 4: ML transformer model (optional, highest accuracy)
    Layer 5: Statistical anomaly (secondary boost)
=======
    Pattern-primary scoring with optional statistical/context boosts.

    Model (per S2766 decision):
        score = pattern_score
        if statistical boost enabled:
            score += SemanticAnalyzer.get_threat_score(...) * statistical_boost_weight
        if context boost enabled and user_id given:
            score += context_score * context_boost_weight
        block when score >= detection_threshold

    Cascade short-circuits on pattern_score >= cascade_hard_threshold
    (0.85). Statistical signals are sourced from
    guard_core.detection_engine.semantic.SemanticAnalyzer so entropy,
    encoding-layer counting, and obfuscation detection share one
    implementation.
>>>>>>> Stashed changes
    """

    def __init__(
        self,
<<<<<<< Updated upstream
        pattern_detector: PatternDetector,
        statistical_detector: StatisticalDetector,
        semantic_analyzer: SemanticAnalyzer,
        config: SecurityConfig,
        transformer_detector: TransformerDetector | None = None,
    ) -> None:
        self.pattern_detector = pattern_detector
        self.statistical_detector = statistical_detector
        self.semantic_analyzer = semantic_analyzer
        self.transformer_detector = transformer_detector
        self.threshold = config.prompt_injection_threshold
        self.statistical_weight = config.prompt_injection_statistical_weight

    def _result(
        self,
        total: float,
        pattern: float,
        stat: float,
        malicious: bool,
        matched: list[str],
    ) -> InjectionScore:
        return {
            "total_score": total,
            "pattern_score": pattern,
            "statistical_score": stat,
            "is_malicious": malicious,
            "matched_patterns": matched,
        }

    async def _check_semantic_layers(self, text: str) -> list[str]:
        """Run semantic + normalized-text pattern layers."""
        matched: list[str] = []

        semantic_result = self.semantic_analyzer.analyze(text)
        if semantic_result.is_suspicious:
            matched.extend(f"semantic: {p}" for p in semantic_result.matched_phrases)

        normalized = semantic_result.normalized_text
        if normalized and normalized != text.lower():
            if await self.pattern_detector.is_suspicious(normalized):
                norm = await self.pattern_detector.get_matched_patterns(normalized)
                matched.extend(f"normalized: {p}" for p in norm)

        return matched

    async def score(self, text: str) -> InjectionScore:
        """
        Score text through all detection layers.

        Fast layers first. ML only if fast layers miss.
        """
        stat_total = self.statistical_detector.detect_anomalies(text)["total"]

        # Layer 1: Pattern matching on raw text
        if await self.pattern_detector.is_suspicious(text):
            m = await self.pattern_detector.get_matched_patterns(text)
            ps = await self.pattern_detector.get_score(text)
            return self._result(1.0, ps, stat_total, True, m)

        # Layers 2-3: Semantic + normalized
        sem = await self._check_semantic_layers(text)
        if sem:
            return self._result(1.0, 0.0, stat_total, True, sem)

        # Layer 4: ML transformer (optional)
        if self.transformer_detector is not None:
            ms = self.transformer_detector.get_score(text)
            if self.transformer_detector.is_suspicious(text):
                return self._result(
                    ms,
                    0.0,
                    0.0,
                    True,
                    [f"ml_transformer: score={ms:.3f}"],
                )

        # Layer 5: Statistical boost
        ps = await self.pattern_detector.get_score(text)
        boost = stat_total * self.statistical_weight
        total = min(1.0, ps + boost)
        return self._result(total, ps, stat_total, total >= self.threshold, [])
=======
        pattern_detector: PatternDetector | None = None,
        semantic_analyzer: SemanticAnalyzer | None = None,
        context_detector: ContextAwareDetector | None = None,
        detection_threshold: float = 0.7,
        enable_statistical_boost: bool = True,
        statistical_boost_weight: float = 0.3,
        context_boost_weight: float = 0.2,
        cascade_hard_threshold: float = 0.85,
    ) -> None:
        self.pattern_detector = pattern_detector
        self.semantic_analyzer = semantic_analyzer if enable_statistical_boost else None
        self.context_detector = context_detector
        self.detection_threshold = max(0.0, min(1.0, detection_threshold))
        self.statistical_boost_weight = max(0.0, min(1.0, statistical_boost_weight))
        self.context_boost_weight = max(0.0, min(1.0, context_boost_weight))
        self.cascade_hard_threshold = max(0.0, min(1.0, cascade_hard_threshold))

    def get_pattern_score(self, text: str) -> tuple[float, list[str]]:
        if not self.pattern_detector:
            return 0.0, []

        patterns = self.pattern_detector.pattern_manager.get_all_patterns(
            enabled_only=True
        )
        if not patterns:
            return 0.0, []

        total_score = 0.0
        match_count = 0
        matched_descriptions: list[str] = []

        for pattern in patterns:
            matches = pattern.match(text)
            if matches:
                match_count += len(matches)
                total_score += pattern.get_score() * len(matches)
                desc = (
                    f"{pattern.pattern_id}: {pattern.description}"
                    if pattern.description
                    else (pattern.pattern_id or "")
                )
                matched_descriptions.append(desc)

        if match_count == 0:
            return 0.0, []

        avg_score_per_match = total_score / match_count
        normalized = min(1.0, avg_score_per_match / 100.0)

        if self.pattern_detector.is_suspicious(text):
            normalized = max(normalized, self.cascade_hard_threshold)

        return normalized, matched_descriptions

    def get_statistical_score(self, text: str) -> float:
        if not self.semantic_analyzer:
            return 0.0
        analysis = self.semantic_analyzer.analyze(text)
        return self.semantic_analyzer.get_threat_score(analysis)

    def get_context_score(
        self,
        text: str,
        context_type: ContextType | None = None,
        user_id: str | None = None,
    ) -> float:
        if not self.context_detector or not user_id:
            return 0.0
        ctx = context_type or ContextType.GENERAL
        return self.context_detector.get_context_score(text, ctx, user_id)

    def score_injection_probability(
        self,
        text: str,
        context_type: ContextType | None = None,
        user_id: str | None = None,
    ) -> InjectionScore:
        pattern_score, matched_patterns = self.get_pattern_score(text)

        if pattern_score >= self.cascade_hard_threshold:
            result: InjectionScore = {
                "total_score": pattern_score,
                "pattern_score": pattern_score,
                "statistical_score": 0.0,
                "context_score": 0.0,
                "components": {
                    "patterns": pattern_score,
                    "statistical": 0.0,
                    "context": 0.0,
                },
                "threshold": self.detection_threshold,
                "is_malicious": True,
                "confidence": 0.95,
                "matched_patterns": matched_patterns,
                "cascade_stopped_at": "pattern",
                "layers_skipped": ["statistical", "context"],
            }
            return result

        statistical_score = self.get_statistical_score(text)
        context_score = self.get_context_score(text, context_type, user_id)

        total_score = (
            pattern_score
            + statistical_score * self.statistical_boost_weight
            + context_score * self.context_boost_weight
        )
        total_score = min(1.0, total_score)

        active_layers = sum(
            1 for s in (pattern_score, statistical_score, context_score) if s > 0.0
        )
        if active_layers == 0:
            confidence = 0.0
        elif active_layers == 1:
            confidence = 0.5
        elif active_layers == 2:
            confidence = 0.75
        else:
            confidence = 0.9

        if pattern_score > 0.8:
            confidence = max(confidence, 0.9)

        return {
            "total_score": total_score,
            "pattern_score": pattern_score,
            "statistical_score": statistical_score,
            "context_score": context_score,
            "components": {
                "patterns": pattern_score,
                "statistical": statistical_score,
                "context": context_score,
            },
            "threshold": self.detection_threshold,
            "is_malicious": total_score >= self.detection_threshold,
            "confidence": confidence,
            "matched_patterns": matched_patterns,
        }

    def is_malicious(
        self,
        text: str,
        context_type: ContextType | None = None,
        user_id: str | None = None,
    ) -> bool:
        return self.score_injection_probability(text, context_type, user_id)[
            "is_malicious"
        ]

    def update_threshold(self, new_threshold: float) -> None:
        self.detection_threshold = max(0.0, min(1.0, new_threshold))
>>>>>>> Stashed changes
