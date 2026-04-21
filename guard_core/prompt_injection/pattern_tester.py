import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from guard_core.prompt_injection.pattern_manager import PatternManager
from guard_core.prompt_injection.pattern_types import InjectionPattern, PatternCategory


def _classify_case(matched: bool, is_malicious: bool) -> str:
    if matched and is_malicious:
        return "tp"
    if matched:
        return "fp"
    if is_malicious:
        return "fn"
    return "tn"


@dataclass
class TestCase:
    """Represents a single test case."""

    text: str
    is_malicious: bool
    category: PatternCategory | None = None
    description: str = ""
    severity: str = "medium"


@dataclass
class PatternTestResult:
    """Results from testing a pattern."""

    pattern_id: str
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    false_positive_rate: float
    recommendation: str
    false_positive_examples: list[str]
    false_negative_examples: list[str]


class PatternTester:
    """
    Test patterns against known attacks and false positives.

    Provides comprehensive testing of injection detection patterns including:
    - Precision/recall/F1 metrics
    - False positive/negative tracking
    - Effectiveness recommendations
    - Test suite management
    """

    def __init__(
        self,
        pattern_manager: PatternManager,
        test_suite_file: str | None = None,
    ):
        """
        Initialize the pattern tester.

        Args:
            pattern_manager: PatternManager containing patterns to test
            test_suite_file: Optional JSON file containing test cases
        """
        self.pattern_manager = pattern_manager
        self.test_cases: list[TestCase] = []
        self.results: dict[str, PatternTestResult] = {}

        if test_suite_file:
            self.load_test_suite(test_suite_file)

    def add_test_case(
        self,
        text: str,
        is_malicious: bool,
        category: PatternCategory | None = None,
        description: str = "",
        severity: str = "medium",
    ) -> None:
        """
        Add a test case to the suite.

        Args:
            text: The text to test
            is_malicious: Whether this is a malicious input
            category: Optional category for targeted testing
            description: Description of the test case
            severity: Severity level (low, medium, high, critical)
        """
        self.test_cases.append(
            TestCase(
                text=text,
                is_malicious=is_malicious,
                category=category,
                description=description,
                severity=severity,
            )
        )

    def load_test_suite(self, file_path: str) -> None:
        """
        Load test cases from a JSON file.

        Args:
            file_path: Path to JSON file containing test cases
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Test suite file not found: {file_path}")

        with path.open("r") as f:
            data = json.load(f)

        for case in data.get("test_cases", []):
            category_str = case.get("category")
            category: PatternCategory | None = None
            if category_str:
                for cat in PatternCategory:
                    if cat.key == category_str:
                        category = cat
                        break

            self.add_test_case(
                text=case["text"],
                is_malicious=case["is_malicious"],
                category=category,
                description=case.get("description", ""),
                severity=case.get("severity", "medium"),
            )

    def save_test_suite(self, file_path: str) -> None:
        """
        Save test cases to a JSON file.

        Args:
            file_path: Path to save test cases
        """
        data = {
            "test_cases": [
                {
                    "text": case.text,
                    "is_malicious": case.is_malicious,
                    "category": case.category.value if case.category else None,
                    "description": case.description,
                    "severity": case.severity,
                }
                for case in self.test_cases
            ]
        }

        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("w") as f:
            json.dump(data, f, indent=2)

    def test_pattern(
        self,
        pattern: InjectionPattern,
        verbose: bool = False,
        category_filter: PatternCategory | None = None,
    ) -> PatternTestResult:
        """
        Test a single pattern against the test suite.

        Args:
            pattern: The pattern to test
            verbose: Whether to print verbose output
            category_filter: Optional category to filter test cases

        Returns:
            PatternTestResult containing metrics and examples
        """
        test_cases = (
            [c for c in self.test_cases if c.category == category_filter]
            if category_filter
            else self.test_cases
        )

        counts, fp_examples, fn_examples = self._tally_pattern_cases(
            pattern, test_cases, verbose
        )
        metrics = self._compute_metrics(counts)

        return PatternTestResult(
            pattern_id=pattern.pattern_id or "unknown",
            true_positives=counts["tp"],
            false_positives=counts["fp"],
            true_negatives=counts["tn"],
            false_negatives=counts["fn"],
            precision=metrics["precision"],
            recall=metrics["recall"],
            f1_score=metrics["f1"],
            accuracy=metrics["accuracy"],
            false_positive_rate=metrics["fpr"],
            recommendation=self._get_recommendation(
                metrics["precision"], metrics["recall"], metrics["fpr"]
            ),
            false_positive_examples=fp_examples[:5],
            false_negative_examples=fn_examples[:5],
        )

    @staticmethod
    def _tally_pattern_cases(
        pattern: InjectionPattern,
        test_cases: list[TestCase],
        verbose: bool,
    ) -> tuple[dict[str, int], list[str], list[str]]:
        counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
        fp_examples: list[str] = []
        fn_examples: list[str] = []

        for case in test_cases:
            matched = bool(pattern.match(case.text))
            bucket = _classify_case(matched, case.is_malicious)
            counts[bucket] += 1
            if bucket == "fp":
                fp_examples.append(case.text[:100])
                if verbose:
                    print(f"FALSE POSITIVE: {case.text[:80]}...")
            elif bucket == "fn":
                fn_examples.append(case.text[:100])
                if verbose:
                    print(f"FALSE NEGATIVE: {case.text[:80]}...")

        return counts, fp_examples, fn_examples

    @staticmethod
    def _compute_metrics(counts: dict[str, int]) -> dict[str, float]:
        tp, fp, tn, fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (
            2 * (precision * recall) / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )
        total = tp + tn + fp + fn
        return {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "accuracy": (tp + tn) / total if total > 0 else 0.0,
            "fpr": fp / (fp + tn) if (fp + tn) > 0 else 0.0,
        }

    def test_all_patterns(
        self,
        verbose: bool = False,
        category_filter: PatternCategory | None = None,
    ) -> dict[str, PatternTestResult]:
        """
        Test all patterns in the manager.

        Args:
            verbose: Whether to print verbose output
            category_filter: Optional category to filter patterns

        Returns:
            Dictionary mapping pattern IDs to test results
        """
        patterns = self.pattern_manager.get_all_patterns()
        if category_filter:
            patterns = [p for p in patterns if p.category == category_filter]

        self.results = {}
        for pattern in patterns:
            if verbose:
                print(f"\nTesting pattern: {pattern.pattern_id}")
                print(f"Description: {pattern.description}")

            result = self.test_pattern(pattern, verbose=verbose)
            pattern_id = pattern.pattern_id or "unknown"
            self.results[pattern_id] = result

            if verbose:
                print(f"Precision: {result.precision:.2%}")
                print(f"Recall: {result.recall:.2%}")
                print(f"F1 Score: {result.f1_score:.2%}")
                print(f"Recommendation: {result.recommendation}")

        return self.results

    def generate_report(
        self,
        output_file: str | None = None,
        sort_by: str = "f1_score",
    ) -> str:
        """
        Generate a comprehensive test report.

        Args:
            output_file: Optional file to save report to
            sort_by: Metric to sort by (f1_score, precision, recall, etc.)

        Returns:
            Report text
        """
        if not self.results:
            return "No test results available. Run test_all_patterns() first."

        sorted_results = sorted(
            self.results.values(),
            key=lambda x: getattr(x, sort_by),
            reverse=True,
        )

        lines: list[str] = ["# Pattern Testing Report", "", "## Summary", ""]
        lines.extend(self._render_summary())
        lines.extend(self._render_top_patterns(sorted_results))
        lines.extend(self._render_improvement_section(sorted_results))

        report = "\n".join(lines)
        if output_file:
            Path(output_file).write_text(report)
        return report

    def _render_summary(self) -> list[str]:
        total = len(self.results)
        high_precision = sum(1 for r in self.results.values() if r.precision >= 0.9)
        high_recall = sum(1 for r in self.results.values() if r.recall >= 0.9)
        high_f1 = sum(1 for r in self.results.values() if r.f1_score >= 0.9)
        return [
            f"- **Total Patterns Tested**: {total}",
            f"- **High Precision (≥90%)**: {high_precision} "
            f"({high_precision / total:.1%})",
            f"- **High Recall (≥90%)**: {high_recall} ({high_recall / total:.1%})",
            f"- **High F1 Score (≥90%)**: {high_f1} ({high_f1 / total:.1%})",
            "",
            "## Pattern Performance",
            "",
        ]

    @staticmethod
    def _render_top_patterns(sorted_results: list[PatternTestResult]) -> list[str]:
        lines = ["### Top 10 Patterns (by F1 Score)", ""]
        for result in sorted_results[:10]:
            lines.extend(
                [
                    f"**{result.pattern_id}**",
                    f"- Precision: {result.precision:.2%}",
                    f"- Recall: {result.recall:.2%}",
                    f"- F1 Score: {result.f1_score:.2%}",
                    f"- Recommendation: {result.recommendation}",
                    "",
                ]
            )
        return lines

    @classmethod
    def _render_improvement_section(
        cls, sorted_results: list[PatternTestResult]
    ) -> list[str]:
        needs_improvement = [r for r in sorted_results if r.f1_score < 0.7]
        if not needs_improvement:
            return []
        lines = ["### Patterns Needing Improvement (F1 < 70%)", ""]
        for result in needs_improvement:
            lines.extend(cls._render_improvement_entry(result))
        return lines

    @staticmethod
    def _render_improvement_entry(result: PatternTestResult) -> list[str]:
        entry = [
            f"**{result.pattern_id}**",
            f"- Precision: {result.precision:.2%}",
            f"- Recall: {result.recall:.2%}",
            f"- F1 Score: {result.f1_score:.2%}",
            f"- False Positive Rate: {result.false_positive_rate:.2%}",
            f"- Recommendation: {result.recommendation}",
        ]
        if result.false_positive_examples:
            entry.append("- False Positive Examples:")
            entry.extend(f"  - `{ex}`" for ex in result.false_positive_examples[:3])
        if result.false_negative_examples:
            entry.append("- False Negative Examples:")
            entry.extend(f"  - `{ex}`" for ex in result.false_negative_examples[:3])
        entry.append("")
        return entry

    def compare_patterns(
        self,
        pattern_a: InjectionPattern,
        pattern_b: InjectionPattern,
    ) -> dict[str, Any]:
        """
        A/B test two pattern variations.

        Args:
            pattern_a: First pattern to compare
            pattern_b: Second pattern to compare

        Returns:
            Comparison results
        """
        result_a = self.test_pattern(pattern_a)
        result_b = self.test_pattern(pattern_b)

        return {
            "pattern_a": {
                "id": pattern_a.pattern_id,
                "precision": result_a.precision,
                "recall": result_a.recall,
                "f1_score": result_a.f1_score,
            },
            "pattern_b": {
                "id": pattern_b.pattern_id,
                "precision": result_b.precision,
                "recall": result_b.recall,
                "f1_score": result_b.f1_score,
            },
            "winner": (
                pattern_a.pattern_id
                if result_a.f1_score > result_b.f1_score
                else pattern_b.pattern_id
            ),
            "f1_improvement": abs(result_a.f1_score - result_b.f1_score),
        }

    def _get_recommendation(
        self,
        precision: float,
        recall: float,
        fpr: float,
    ) -> str:
        """
        Get recommendation based on metrics.

        Args:
            precision: Precision score
            recall: Recall score
            fpr: False positive rate

        Returns:
            Recommendation text
        """
        if precision >= 0.95 and recall >= 0.95:
            return "Excellent - Keep as is"
        elif precision >= 0.9 and recall >= 0.8:
            return "Good - Monitor performance"
        elif precision < 0.7 and fpr > 0.1:
            return "High false positive rate - Consider tightening pattern"
        elif recall < 0.7:
            return "Low recall - Pattern misses many attacks, consider expanding"
        elif precision < 0.8:
            return "Moderate false positives - Review and refine"
        else:
            return "Acceptable - Monitor and adjust as needed"
