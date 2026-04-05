import re

from guard_core.detection_engine.compiler import PatternCompiler
from guard_core.prompt_injection.patterns import get_default_patterns
from guard_core.prompt_injection.types import InjectionPattern, PatternCategory


class PatternDetector:
    """
    Detects prompt injection attempts using regex pattern matching.

    Uses the detection_engine PatternCompiler for ReDoS-safe matching
    with caching and timeout protection.
    """

    def __init__(
        self,
        sensitivity: float = 0.5,
        custom_patterns: list[str] | None = None,
        compiler: PatternCompiler | None = None,
    ) -> None:
        self.sensitivity = max(0.0, min(1.0, sensitivity))
        self.compiler = compiler or PatternCompiler()
        self._patterns = get_default_patterns()

        if custom_patterns:
            for idx, pattern_str in enumerate(custom_patterns):
                try:
                    self._patterns.append(
                        InjectionPattern(
                            pattern_id=f"custom_{idx}",
                            pattern=pattern_str,
                            category=PatternCategory.INSTRUCTION_OVERRIDE,
                            weight=1.0,
                            confidence=0.8,
                            description=f"Custom pattern: {pattern_str[:50]}",
                        )
                    )
                except (ValueError, re.error):
                    continue

    def _get_enabled_patterns(self) -> list[InjectionPattern]:
        return [p for p in self._patterns if p.enabled]

    def _accumulate_matches(self, text: str) -> tuple[float, int]:
        """Sum weighted scores and match count across all patterns."""
        total_score = 0.0
        match_count = 0
        for pattern in self._get_enabled_patterns():
            matches = pattern.match(text)
            if matches:
                match_count += len(matches)
                total_score += pattern.get_score() * len(matches)
        return total_score, match_count

    async def is_suspicious(self, text: str) -> bool:
        """Check if text contains suspicious injection patterns."""
        if not text:
            return False

        total_score, match_count = self._accumulate_matches(text)

        if match_count == 0:
            return False

        if self.sensitivity <= 0.5:
            return True

        avg = total_score / match_count
        threshold = (1.0 - self.sensitivity) * 100
        return avg >= threshold

    async def get_matched_patterns(self, text: str) -> list[str]:
        """Get list of pattern descriptions that matched."""
        if not text:
            return []

        matched: list[str] = []
        for pattern in self._get_enabled_patterns():
            if pattern.match(text):
                desc = (
                    f"{pattern.pattern_id}: {pattern.description}"
                    if pattern.description
                    else str(pattern.pattern_id)
                )
                matched.append(desc)
        return matched

    async def get_score(self, text: str) -> float:
        """
        Calculate normalized pattern detection score (0-1).

        Returns the average score per match, normalized to 0-1.
        """
        if not text:
            return 0.0

        total_score, match_count = self._accumulate_matches(text)

        if match_count == 0:
            return 0.0

        avg = total_score / match_count
        return min(1.0, avg / 100.0)
