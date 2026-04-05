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


class InjectionScorer:
    """
    Score injection probability using multiple detection layers.

    Layer 1: Pattern matching on raw text (fast, primary signal)
    Layer 2: Semantic analysis on normalized text (synonym/homoglyph)
    Layer 3: Pattern matching on normalized text (post-normalization)
    Layer 4: ML transformer model (optional, highest accuracy)
    Layer 5: Statistical anomaly (secondary boost)
    """

    def __init__(
        self,
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
