import math
import re
from collections import Counter
from typing import TypedDict


class AnomalyScores(TypedDict):
    """Statistical anomaly scores breakdown."""

    entropy: float
    char_distribution: float
    token_complexity: float
    delimiter_imbalance: float
    total: float


class StatisticalDetector:
    """
    Detect anomalies in text structure using statistical analysis.

    Analyzes entropy, character distribution, token complexity,
    and delimiter imbalance to identify obfuscated or encoded content.
    """

    NORMAL_ENTROPY_THRESHOLD = 4.5
    HIGH_ENTROPY_THRESHOLD = 5.5
    MIN_TEXT_LENGTH = 10

    def __init__(
        self,
        entropy_weight: float = 0.3,
        char_dist_weight: float = 0.2,
        complexity_weight: float = 0.2,
        delimiter_weight: float = 0.3,
    ) -> None:
        total = entropy_weight + char_dist_weight + complexity_weight + delimiter_weight
        if total > 0:
            self.entropy_weight = entropy_weight / total
            self.char_dist_weight = char_dist_weight / total
            self.complexity_weight = complexity_weight / total
            self.delimiter_weight = delimiter_weight / total
        else:
            self.entropy_weight = 0.25
            self.char_dist_weight = 0.25
            self.complexity_weight = 0.25
            self.delimiter_weight = 0.25

    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text in bits per character."""
        if not text:
            return 0.0

        char_counts = Counter(text)
        length = len(text)
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        return entropy

    def _char_ratios(self, text: str) -> tuple[float, float, float]:
        """Calculate special, alpha, digit ratios."""
        length = len(text)
        alphas = sum(1 for c in text if c.isalpha())
        digits = sum(1 for c in text if c.isdigit())
        spaces = sum(1 for c in text if c.isspace())
        special = length - alphas - digits - spaces
        return special / length, alphas / length, digits / length

    def analyze_char_distribution(self, text: str) -> float:
        """Analyze character distribution for anomalies. Returns 0-1."""
        if not text or len(text) < self.MIN_TEXT_LENGTH:
            return 0.0

        special_ratio, alpha_ratio, digit_ratio = self._char_ratios(text)

        anomaly_score = 0.0
        if special_ratio > 0.3:
            anomaly_score += min(0.5, (special_ratio - 0.3) * 2)
        if alpha_ratio < 0.4:
            anomaly_score += min(0.3, (0.4 - alpha_ratio) * 1.5)
        if digit_ratio > 0.2:
            anomaly_score += min(0.2, (digit_ratio - 0.2) * 1.0)
        return min(1.0, anomaly_score)

    def _alternation_ratio(self, tokens: list[str]) -> float:
        """Calculate word/special alternation ratio."""
        alternating = 0
        for i in range(len(tokens) - 1):
            curr_is_word = any(c.isalnum() for c in tokens[i])
            next_is_word = any(c.isalnum() for c in tokens[i + 1])
            if curr_is_word != next_is_word:
                alternating += 1
        return alternating / max(1, len(tokens) - 1)

    @staticmethod
    def _is_special_token(token: str) -> bool:
        return not any(c.isalnum() for c in token)

    def analyze_token_complexity(self, text: str) -> float:
        """Analyze token complexity and patterns. Returns 0-1."""
        if not text or len(text) < self.MIN_TEXT_LENGTH:
            return 0.0

        tokens = re.findall(r"\w+|[^\w\s]+", text)
        if not tokens:
            return 0.0

        complexity_score = 0.0
        avg_length = sum(len(t) for t in tokens) / len(tokens)
        if avg_length < 2.0:
            complexity_score += 0.3

        special_count = sum(1 for t in tokens if self._is_special_token(t))
        if special_count > len(tokens) * 0.3:
            complexity_score += 0.4

        if self._alternation_ratio(tokens) > 0.6:
            complexity_score += 0.3

        return min(1.0, complexity_score)

    def has_delimiter_imbalance(self, text: str) -> float:
        """Check for imbalanced delimiters. Returns 0-1."""
        if not text:
            return 0.0

        imbalance_score = 0.0

        bracket_pairs = [("(", ")"), ("[", "]"), ("{", "}"), ("<", ">")]
        for open_char, close_char in bracket_pairs:
            open_count = text.count(open_char)
            close_count = text.count(close_char)
            if open_count != close_count:
                total = open_count + close_count
                if total > 0:
                    diff = abs(open_count - close_count)
                    imbalance_score += min(0.25, diff / total)

        for quote_char in ["'", '"', "`"]:
            count = text.count(quote_char)
            if count % 2 != 0:
                imbalance_score += 0.15

        delimiter_chars = "()[]{}\"'`<>"
        delimiter_count = sum(1 for c in text if c in delimiter_chars)
        delimiter_ratio = delimiter_count / len(text)

        if delimiter_ratio > 0.2:
            imbalance_score += min(0.3, (delimiter_ratio - 0.2) * 1.5)

        return min(1.0, imbalance_score)

    def detect_anomalies(self, text: str) -> AnomalyScores:
        """Detect all statistical anomalies and return detailed scores."""
        if not text or len(text) < self.MIN_TEXT_LENGTH:
            return {
                "entropy": 0.0,
                "char_distribution": 0.0,
                "token_complexity": 0.0,
                "delimiter_imbalance": 0.0,
                "total": 0.0,
            }

        entropy = self.calculate_entropy(text)
        char_dist_anomaly = self.analyze_char_distribution(text)
        complexity_anomaly = self.analyze_token_complexity(text)
        delimiter_anomaly = self.has_delimiter_imbalance(text)

        entropy_anomaly = 0.0
        if entropy > self.NORMAL_ENTROPY_THRESHOLD:
            if entropy >= self.HIGH_ENTROPY_THRESHOLD:
                entropy_anomaly = 0.7 + min(
                    0.3, (entropy - self.HIGH_ENTROPY_THRESHOLD) / 2.5 * 0.3
                )
            else:
                entropy_anomaly = (
                    (entropy - self.NORMAL_ENTROPY_THRESHOLD)
                    / (self.HIGH_ENTROPY_THRESHOLD - self.NORMAL_ENTROPY_THRESHOLD)
                    * 0.7
                )

        total_score = (
            entropy_anomaly * self.entropy_weight
            + char_dist_anomaly * self.char_dist_weight
            + complexity_anomaly * self.complexity_weight
            + delimiter_anomaly * self.delimiter_weight
        )

        return {
            "entropy": entropy_anomaly,
            "char_distribution": char_dist_anomaly,
            "token_complexity": complexity_anomaly,
            "delimiter_imbalance": delimiter_anomaly,
            "total": min(1.0, total_score),
        }

    def is_anomalous(self, text: str, threshold: float = 0.6) -> bool:
        """Check if text is statistically anomalous."""
        scores = self.detect_anomalies(text)
        return scores["total"] >= threshold
