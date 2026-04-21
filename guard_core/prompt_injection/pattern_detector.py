import re

from guard_core.detection_engine.compiler import PatternCompiler
<<<<<<< Updated upstream
from guard_core.prompt_injection.patterns import get_default_patterns
from guard_core.prompt_injection.types import InjectionPattern, PatternCategory


class PatternDetector:
    """
    Detects prompt injection attempts using regex pattern matching.

    Uses the detection_engine PatternCompiler for ReDoS-safe matching
    with caching and timeout protection.
    """

=======
from guard_core.prompt_injection.pattern_manager import PatternManager

_SAFETY_COMPILER = PatternCompiler()


class PatternDetector:
>>>>>>> Stashed changes
    def __init__(
        self,
        sensitivity: float = 0.5,
        custom_patterns: list[str] | None = None,
<<<<<<< Updated upstream
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
=======
        pattern_manager: "PatternManager | None" = None,
    ) -> None:
        self.sensitivity = max(0.0, min(1.0, sensitivity))
        self.custom_patterns = custom_patterns or []

        if pattern_manager:
            self.pattern_manager = pattern_manager
        else:
            self.pattern_manager = self._create_default_pattern_manager()

    def _create_default_pattern_manager(self) -> "PatternManager":
        from guard_core.prompt_injection.pattern_library import (
            create_default_pattern_manager,
        )
        from guard_core.prompt_injection.pattern_types import (
            InjectionPattern,
            PatternCategory,
        )

        manager = create_default_pattern_manager()

        for idx, pattern_str in enumerate(self.custom_patterns):
            is_safe, _ = _SAFETY_COMPILER.validate_pattern_safety(pattern_str)
            if not is_safe:
                continue
            try:
                custom_pattern = InjectionPattern(
                    pattern_id=f"custom_pattern_{idx}",
                    pattern=pattern_str,
                    category=PatternCategory.INSTRUCTION_OVERRIDE,
                    weight=1.0,
                    description=f"Custom pattern: {pattern_str[:50]}...",
                    confidence=0.8,
                )
                manager.add_pattern(custom_pattern, persist=False)
            except (ValueError, re.error):
                continue

        return manager

    def is_suspicious(self, text: str) -> bool:
        if not text:
            return False

        patterns = self.pattern_manager.get_all_patterns(enabled_only=True)
        if not patterns:
            return False

        total_score = 0.0
        match_count = 0

        for pattern in patterns:
>>>>>>> Stashed changes
            matches = pattern.match(text)
            if matches:
                match_count += len(matches)
                total_score += pattern.get_score() * len(matches)
<<<<<<< Updated upstream
        return total_score, match_count

    async def is_suspicious(self, text: str) -> bool:
        """Check if text contains suspicious injection patterns."""
        if not text:
            return False

        total_score, match_count = self._accumulate_matches(text)
=======
>>>>>>> Stashed changes

        if match_count == 0:
            return False

<<<<<<< Updated upstream
        if self.sensitivity <= 0.5:
            return True

        avg = total_score / match_count
        threshold = (1.0 - self.sensitivity) * 100
        return avg >= threshold

    async def get_matched_patterns(self, text: str) -> list[str]:
        """Get list of pattern descriptions that matched."""
=======
        if self.sensitivity <= 0.5 and match_count > 0:
            return True

        avg_score_per_match = total_score / match_count if match_count > 0 else 0
        threshold = (1.0 - self.sensitivity) * 100

        return avg_score_per_match >= threshold

    def get_matched_patterns(self, text: str) -> list[str]:
>>>>>>> Stashed changes
        if not text:
            return []

        matched: list[str] = []
<<<<<<< Updated upstream
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
=======
        patterns = self.pattern_manager.get_all_patterns(enabled_only=True)

        for pattern in patterns:
            if pattern.match(text):
                desc: str = (
                    f"{pattern.pattern_id}: {pattern.description}"
                    if pattern.description is not None
                    else pattern.pattern_id
                )
                matched.append(desc)

        return matched

    def add_custom_pattern(self, pattern: str) -> bool:
        from guard_core.prompt_injection.pattern_types import (
            InjectionPattern,
            PatternCategory,
        )

        is_safe, _ = _SAFETY_COMPILER.validate_pattern_safety(pattern)
        if not is_safe:
            return False

        try:
            custom_pattern = InjectionPattern(
                pattern_id=f"runtime_custom_{len(self.custom_patterns) + 1}",
                pattern=pattern,
                category=PatternCategory.INSTRUCTION_OVERRIDE,
                weight=1.0,
                description=f"Runtime custom pattern: {pattern[:50]}...",
                confidence=0.8,
            )
            self.pattern_manager.add_pattern(custom_pattern, persist=False)
            self.custom_patterns.append(pattern)
            return True
        except (ValueError, re.error):
            return False

    def remove_custom_pattern(self, pattern: str) -> bool:
        if pattern not in self.custom_patterns:
            return False

        idx = self.custom_patterns.index(pattern)
        pattern_id = f"runtime_custom_{idx + 1}"

        self.custom_patterns.remove(pattern)
        return self.pattern_manager.remove_pattern(pattern_id, persist=False)

    def clear_custom_patterns(self) -> None:
        for idx in range(len(self.custom_patterns)):
            pattern_id = f"runtime_custom_{idx + 1}"
            self.pattern_manager.remove_pattern(pattern_id, persist=False)

        self.custom_patterns.clear()

    def get_pattern_count(self) -> dict[str, int]:
        stats = self.pattern_manager.get_pattern_stats()
        return {
            "total_patterns": stats["total_patterns"],
            "enabled_patterns": stats["enabled_patterns"],
            "custom_patterns_added": len(self.custom_patterns),
        }
>>>>>>> Stashed changes
