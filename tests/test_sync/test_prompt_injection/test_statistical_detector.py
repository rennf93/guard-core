from guard_core.sync.prompt_injection.statistical_detector import StatisticalDetector


class TestStatisticalDetector:
    def test_normal_text(self) -> None:
        detector = StatisticalDetector()
        scores = detector.detect_anomalies("This is a normal sentence about cooking.")
        assert scores["total"] < 0.3

    def test_empty_text(self) -> None:
        detector = StatisticalDetector()
        scores = detector.detect_anomalies("")
        assert scores["total"] == 0.0

    def test_short_text(self) -> None:
        detector = StatisticalDetector()
        scores = detector.detect_anomalies("hi")
        assert scores["total"] == 0.0

    def test_high_entropy_text(self) -> None:
        detector = StatisticalDetector()
        # Random-looking text with high entropy
        text = "a8f3k2j5h9d1m4p7q0w6e3r8t5y2u9i0o1l4s7"
        scores = detector.detect_anomalies(text)
        assert scores["entropy"] > 0.0

    def test_special_char_heavy(self) -> None:
        detector = StatisticalDetector()
        text = "!!!@@@###$$$%%%^^^&&&***((()))"
        scores = detector.detect_anomalies(text)
        assert scores["char_distribution"] > 0.0

    def test_delimiter_imbalance(self) -> None:
        detector = StatisticalDetector()
        text = "((((((((text with lots of unbalanced brackets"
        scores = detector.detect_anomalies(text)
        assert scores["delimiter_imbalance"] > 0.0

    def test_is_anomalous_normal(self) -> None:
        detector = StatisticalDetector()
        assert not detector.is_anomalous("This is a perfectly normal sentence.")

    def test_is_anomalous_with_threshold(self) -> None:
        detector = StatisticalDetector()
        # Very low threshold should flag more things
        text = "a8f3k2j5h9d1m4p7q0w6e3r8t5y2u9i0o1l4s7"
        assert detector.is_anomalous(text, threshold=0.05)

    def test_calculate_entropy(self) -> None:
        detector = StatisticalDetector()
        # Single character has 0 entropy
        assert detector.calculate_entropy("aaaa") == 0.0
        # More variety = higher entropy
        entropy = detector.calculate_entropy("abcdefghij")
        assert entropy > 3.0

    def test_token_complexity_normal(self) -> None:
        detector = StatisticalDetector()
        text = "The quick brown fox jumps over the lazy dog"
        score = detector.analyze_token_complexity(text)
        assert score < 0.3

    def test_token_complexity_high(self) -> None:
        detector = StatisticalDetector()
        # Very short tokens with lots of special chars
        text = "a.b.c.d.e.f.g.h.i.j.k.l.m"
        score = detector.analyze_token_complexity(text)
        assert score > 0.0

    def test_custom_weights(self) -> None:
        detector = StatisticalDetector(
            entropy_weight=1.0,
            char_dist_weight=0.0,
            complexity_weight=0.0,
            delimiter_weight=0.0,
        )
        # Should weight only entropy
        text = "a8f3k2j5h9d1m4p7q0w6e3r8t5y2u9i0o1l4s7"
        scores = detector.detect_anomalies(text)
        # Total should be driven by entropy only
        assert scores["total"] > 0.0

    def test_entropy_empty_string(self) -> None:
        detector = StatisticalDetector()
        assert detector.calculate_entropy("") == 0.0

    def test_char_distribution_empty(self) -> None:
        detector = StatisticalDetector()
        assert detector.analyze_char_distribution("") == 0.0

    def test_char_distribution_short(self) -> None:
        detector = StatisticalDetector()
        assert detector.analyze_char_distribution("hi") == 0.0

    def test_char_distribution_low_alpha(self) -> None:
        detector = StatisticalDetector()
        # Text with very low alpha content
        score = detector.analyze_char_distribution("123456789012345")
        assert score > 0.0

    def test_token_complexity_empty(self) -> None:
        detector = StatisticalDetector()
        assert detector.analyze_token_complexity("") == 0.0

    def test_token_complexity_short(self) -> None:
        detector = StatisticalDetector()
        assert detector.analyze_token_complexity("hi") == 0.0

    def test_token_complexity_no_tokens(self) -> None:
        detector = StatisticalDetector()
        assert detector.analyze_token_complexity("          ") == 0.0

    def test_delimiter_imbalance_empty(self) -> None:
        detector = StatisticalDetector()
        assert detector.has_delimiter_imbalance("") == 0.0

    def test_delimiter_odd_quotes(self) -> None:
        detector = StatisticalDetector()
        score = detector.has_delimiter_imbalance("he said 'hello")
        assert score > 0.0

    def test_excessive_delimiters(self) -> None:
        detector = StatisticalDetector()
        # Text with >20% delimiter characters
        text = "((((()))))[[[[]]]]{}{}{}{}\"\"''"
        score = detector.has_delimiter_imbalance(text)
        assert score > 0.0

    def test_very_high_entropy(self) -> None:
        detector = StatisticalDetector()
        # Extremely varied text to trigger high entropy path
        import string

        text = (string.ascii_letters + string.digits + string.punctuation) * 3
        scores = detector.detect_anomalies(text)
        assert scores["entropy"] > 0.5

    def test_all_zero_weights(self) -> None:
        detector = StatisticalDetector(
            entropy_weight=0.0,
            char_dist_weight=0.0,
            complexity_weight=0.0,
            delimiter_weight=0.0,
        )
        scores = detector.detect_anomalies("test text for zero weights analysis input")
        # Should use equal weights
        assert isinstance(scores["total"], float)
