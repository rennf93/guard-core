from guard_core.sync.detection_engine import (
    ContentPreprocessor,
    PatternCompiler,
    PerformanceMonitor,
    SemanticAnalyzer,
)


def test_pattern_compiler() -> None:
    compiler = PatternCompiler()

    safe_pattern = r"<script[^>]*>"
    is_safe, reason = compiler.validate_pattern_safety(safe_pattern)
    assert is_safe is True

    dangerous_pattern = r"(.*)+"
    is_safe, reason = compiler.validate_pattern_safety(dangerous_pattern)
    assert is_safe is False
    assert "dangerous" in reason.lower()


def test_content_preprocessor() -> None:
    preprocessor = ContentPreprocessor()

    content = "\uff53\uff43\uff52\uff49\uff50\uff54"
    processed = preprocessor.preprocess(content)
    assert "script" in processed.lower()

    attack = "<script>alert('xss')</script>" + "a" * 10000
    processed = preprocessor.preprocess(attack)
    assert "<script>" in processed
    assert len(processed) <= preprocessor.max_content_length


def test_semantic_analyzer() -> None:
    analyzer = SemanticAnalyzer()

    xss_content = "<script>alert('xss')</script>"
    analysis = analyzer.analyze(xss_content)
    assert analysis["attack_probabilities"]["xss"] > 0.4

    sql_content = "' OR '1'='1' UNION SELECT * FROM users--"
    analysis = analyzer.analyze(sql_content)
    assert analysis["attack_probabilities"]["sql"] > 0.4


def test_performance_monitor() -> None:
    monitor = PerformanceMonitor()

    monitor.record_metric("test_pattern", 0.01, 100, True)
    monitor.record_metric("test_pattern", 0.05, 200, False)
    monitor.record_metric("slow_pattern", 0.2, 300, False)

    stats = monitor.get_summary_stats()
    assert stats["total_executions"] == 3
    assert stats["match_rate"] > 0

    slow = monitor.get_slow_patterns()
    assert len(slow) > 0
    assert slow[0]["pattern"] == "slow_pattern"
