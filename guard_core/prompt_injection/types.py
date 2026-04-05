import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PatternCategory(Enum):
    """Categories of prompt injection patterns with default weights."""

    INSTRUCTION_OVERRIDE = ("instruction_override", 10)
    ROLE_SWITCHING = ("role_switching", 8)
    CONTEXT_BREAKING = ("context_breaking", 7)
    PROMPT_LEAKAGE = ("prompt_leakage", 6)
    ENCODING_OBFUSCATION = ("encoding_obfuscation", 9)
    JAILBREAK_ATTEMPTS = ("jailbreak_attempts", 10)
    DELIMITER_CONFUSION = ("delimiter_confusion", 5)
    COMMAND_INJECTION = ("command_injection", 8)

    def __init__(self, key: str, default_weight: int) -> None:
        self.key = key
        self.default_weight = default_weight


@dataclass
class InjectionPattern:
    """A single prompt injection detection pattern."""

    pattern: str
    category: PatternCategory
    weight: float = 1.0
    confidence: float = 1.0
    description: str = ""
    enabled: bool = True
    pattern_id: str | None = None

    _compiled: re.Pattern[str] | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.weight = max(0.0, self.weight)
        self.confidence = max(0.0, min(1.0, self.confidence))

        if self.pattern_id is None:
            pattern_prefix = re.sub(r"[^a-z0-9]", "", self.pattern[:20].lower())
            self.pattern_id = f"{self.category.key}_{pattern_prefix}"

        self._compile()

    def _compile(self) -> None:
        try:
            self._compiled = re.compile(
                self.pattern,
                re.IGNORECASE | re.MULTILINE,
            )
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}") from e

    def match(self, text: str) -> list[re.Match[str]]:
        if not self.enabled or not self._compiled:
            return []
        return list(self._compiled.finditer(text))

    def get_score(self) -> float:
        return self.category.default_weight * self.weight * self.confidence


class PromptInjectionAttempt(Exception):
    """Raised when a prompt injection attempt is detected."""

    def __init__(
        self,
        matched_patterns: list[str],
        detection_layer: str,
        threat_score: float,
        detection_metadata: dict[str, Any] | None = None,
    ) -> None:
        self.matched_patterns = matched_patterns
        self.detection_layer = detection_layer
        self.threat_score = threat_score
        self.detection_metadata = detection_metadata or {}
        super().__init__(
            f"Prompt injection detected: layer={detection_layer}, "
            f"score={threat_score:.2f}, patterns={matched_patterns}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "matched_patterns": self.matched_patterns,
            "detection_layer": self.detection_layer,
            "threat_score": self.threat_score,
            "detection_metadata": self.detection_metadata,
        }
