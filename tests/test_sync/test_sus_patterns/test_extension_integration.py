from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager


def test_component_initialization(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    manager = sus_patterns_manager_with_detection

    assert manager._compiler is not None
    assert manager._preprocessor is not None
    assert manager._semantic_analyzer is not None
    assert manager._performance_monitor is not None

    status = manager.get_component_status()
    assert status["compiler"] is True
    assert status["preprocessor"] is True
    assert status["semantic_analyzer"] is True
    assert status["performance_monitor"] is True


def test_extended_detection(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    manager = sus_patterns_manager_with_detection

    xss_content = "<script>alert('xss')</script>"
    is_threat, pattern = manager.detect_pattern_match(xss_content, "127.0.0.1", "test")
    assert is_threat is True
    assert pattern is not None

    sql_content = "SELECT%20*%20FROM%20users"
    is_threat, pattern = manager.detect_pattern_match(sql_content, "127.0.0.1", "test")
    assert is_threat is True


def test_performance_monitoring(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    manager = sus_patterns_manager_with_detection

    test_contents = [
        "normal content",
        "<script>alert(1)</script>",
        "SELECT * FROM users",
    ]

    for content in test_contents:
        manager.detect_pattern_match(content, "127.0.0.1", "test")

    stats = manager.get_performance_stats()
    assert stats is not None
    assert "summary" in stats
    assert stats["summary"]["total_executions"] >= 3

    assert stats["summary"]["total_patterns"] >= 1


def test_semantic_threshold_configuration(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    manager = sus_patterns_manager_with_detection

    manager.configure_semantic_threshold(0.5)
    assert manager._semantic_threshold == 0.5

    manager.configure_semantic_threshold(2.0)
    assert manager._semantic_threshold == 1.0

    manager.configure_semantic_threshold(-1.0)
    assert manager._semantic_threshold == 0.0


def test_compiler_timeout_protection(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    manager = sus_patterns_manager_with_detection

    slow_pattern_content = "a" * 1000 + "b"

    is_threat, pattern = manager.detect_pattern_match(
        slow_pattern_content, "127.0.0.1", "test"
    )


def test_preprocessor_normalization(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    manager = sus_patterns_manager_with_detection

    encoded_attacks = [
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "<script>alert(1)</script>",
    ]

    for encoded in encoded_attacks:
        is_threat, pattern = manager.detect_pattern_match(encoded, "127.0.0.1", "test")
        assert is_threat is True
