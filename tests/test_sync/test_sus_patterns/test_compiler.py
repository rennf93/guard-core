import concurrent.futures
import re
import time
from unittest.mock import MagicMock, patch

import pytest

from guard_core.sync.detection_engine.compiler import PatternCompiler


@pytest.fixture
def compiler() -> PatternCompiler:
    return PatternCompiler(default_timeout=5.0, max_cache_size=100)


def test_initialization() -> None:
    compiler = PatternCompiler()
    assert compiler.default_timeout == 5.0
    assert compiler.max_cache_size == 1000
    assert len(compiler._compiled_cache) == 0
    assert len(compiler._cache_order) == 0

    compiler = PatternCompiler(default_timeout=10.0, max_cache_size=500)
    assert compiler.default_timeout == 10.0
    assert compiler.max_cache_size == 500

    compiler = PatternCompiler(max_cache_size=10000)
    assert compiler.max_cache_size == 5000


def test_compile_pattern_sync(compiler: PatternCompiler) -> None:
    pattern = r"test\d+"
    compiled = compiler.compile_pattern_sync(pattern)
    assert isinstance(compiled, re.Pattern)
    assert compiled.search("test123") is not None
    assert compiled.search("test") is None

    pattern = r"TEST\d+"
    compiled = compiler.compile_pattern_sync(pattern, flags=0)
    assert compiled.search("TEST123") is not None
    assert compiled.search("test123") is None


def test_compile_pattern_cache_hit(compiler: PatternCompiler) -> None:
    pattern = r"cached_pattern\d+"

    compiled1 = compiler.compile_pattern(pattern)
    assert isinstance(compiled1, re.Pattern)

    compiled2 = compiler.compile_pattern(pattern)
    assert compiled1 is compiled2

    cache_key = f"{hash(pattern)}:{re.IGNORECASE | re.MULTILINE}"
    assert cache_key in compiler._compiled_cache
    assert cache_key in compiler._cache_order
    assert compiler._cache_order[-1] == cache_key


def test_compile_pattern_cache_miss(compiler: PatternCompiler) -> None:
    compiler.max_cache_size = 3
    patterns = [f"pattern_{i}" for i in range(3)]

    for pattern in patterns:
        compiler.compile_pattern(pattern)

    assert len(compiler._compiled_cache) == 3
    assert len(compiler._cache_order) == 3

    new_pattern = "pattern_new"
    compiler.compile_pattern(new_pattern)

    assert len(compiler._compiled_cache) == 3
    assert len(compiler._cache_order) == 3

    first_key = f"{hash(patterns[0])}:{re.IGNORECASE | re.MULTILINE}"
    assert first_key not in compiler._compiled_cache

    new_key = f"{hash(new_pattern)}:{re.IGNORECASE | re.MULTILINE}"
    assert new_key in compiler._compiled_cache


def test_compile_pattern_concurrent_access(compiler: PatternCompiler) -> None:
    pattern = r"concurrent_pattern"

    results = [compiler.compile_pattern(pattern) for _ in range(10)]

    first_result = results[0]
    assert all(result is first_result for result in results)

    assert len(compiler._compiled_cache) == 1


def test_validate_pattern_safety_dangerous_patterns(compiler: PatternCompiler) -> None:
    dangerous_patterns = [
        r"(.*)+",
        r"(.+)+",
        r"([a-z]*)+",
        r"([a-z]+)+",
        r".*.*",
        r".+.+",
    ]

    for pattern in dangerous_patterns:
        is_safe, reason = compiler.validate_pattern_safety(pattern)
        assert is_safe is False
        assert "dangerous" in reason.lower()


def test_validate_pattern_safety_slow_pattern(compiler: PatternCompiler) -> None:
    slow_pattern = r"^[a-z]+$"

    call_count = 0
    start_time = time.time()

    def mock_time() -> float:
        nonlocal call_count
        call_count += 1
        if call_count % 2 == 0:
            return start_time + 0.06
        else:
            return start_time

    with patch("time.time", side_effect=mock_time):
        is_safe, reason = compiler.validate_pattern_safety(slow_pattern)
        assert is_safe is False
        assert "timed out on test string" in reason


def test_validate_pattern_safety_exception(compiler: PatternCompiler) -> None:
    pattern = r"test_pattern"

    with patch.object(
        compiler, "compile_pattern_sync", side_effect=Exception("Test error")
    ):
        is_safe, reason = compiler.validate_pattern_safety(pattern)
        assert is_safe is False
        assert reason == "Pattern validation failed: Test error"


def test_validate_pattern_safety_safe_pattern(compiler: PatternCompiler) -> None:
    safe_patterns = [
        r"<script[^>]*>",
        r"\d{3}-\d{3}-\d{4}",
        r"[a-zA-Z0-9]+",
        r"https?://[^\s]+",
    ]

    for pattern in safe_patterns:
        is_safe, reason = compiler.validate_pattern_safety(pattern)
        assert is_safe is True
        assert reason == "Pattern appears safe"


def test_validate_pattern_safety_timeout() -> None:
    compiler = PatternCompiler()

    pattern = r"test_pattern"

    with patch("concurrent.futures.ThreadPoolExecutor") as mock_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = concurrent.futures.TimeoutError()
        mock_executor.return_value.__enter__.return_value.submit.return_value = (
            mock_future
        )

        is_safe, reason = compiler.validate_pattern_safety(pattern)

        assert is_safe is False
        assert "Pattern timed out on test string" in reason


def test_validate_pattern_safety_custom_test_strings(compiler: PatternCompiler) -> None:
    pattern = r"test\d+"
    test_strings = ["test123", "test456", "test789"]

    is_safe, reason = compiler.validate_pattern_safety(pattern, test_strings)
    assert is_safe is True
    assert reason == "Pattern appears safe"


def test_create_safe_matcher(compiler: PatternCompiler) -> None:
    pattern = r"test\d+"
    matcher = compiler.create_safe_matcher(pattern)

    result = matcher("test123")
    assert result is not None
    assert result.group() == "test123"

    result = matcher("test")
    assert result is None


def test_create_safe_matcher_with_timeout(compiler: PatternCompiler) -> None:
    pattern = r"test.*"
    matcher = compiler.create_safe_matcher(pattern, timeout=0.1)

    with patch("concurrent.futures.ThreadPoolExecutor") as mock_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = concurrent.futures.TimeoutError()
        mock_future.cancel.return_value = True
        mock_executor.return_value.__enter__.return_value.submit.return_value = (
            mock_future
        )

        result = matcher("test123")
        assert result is None
        mock_future.cancel.assert_called_once()


def test_create_safe_matcher_with_exception(compiler: PatternCompiler) -> None:
    pattern = r"test.*"
    matcher = compiler.create_safe_matcher(pattern)

    with patch("concurrent.futures.ThreadPoolExecutor") as mock_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = Exception("Test error")
        mock_executor.return_value.__enter__.return_value.submit.return_value = (
            mock_future
        )

        result = matcher("test123")
        assert result is None


def test_batch_compile(compiler: PatternCompiler) -> None:
    patterns = [
        r"pattern1\d+",
        r"pattern2\w+",
        r"pattern3[a-z]+",
    ]

    compiled = compiler.batch_compile(patterns, validate=False)
    assert len(compiled) == 3
    for pattern in patterns:
        assert pattern in compiled
        assert isinstance(compiled[pattern], re.Pattern)


def test_batch_compile_with_validation(compiler: PatternCompiler) -> None:
    patterns = [
        r"safe_pattern\d+",
        r"(.*)+",
        r"another_safe\w+",
    ]

    compiled = compiler.batch_compile(patterns, validate=True)
    assert len(compiled) == 2
    assert patterns[0] in compiled
    assert patterns[1] not in compiled
    assert patterns[2] in compiled


def test_batch_compile_with_invalid_pattern(compiler: PatternCompiler) -> None:
    patterns = [
        r"valid_pattern",
        r"invalid(pattern",
        r"another_valid",
    ]

    compiled = compiler.batch_compile(patterns, validate=False)
    assert len(compiled) == 2
    assert patterns[0] in compiled
    assert patterns[1] not in compiled
    assert patterns[2] in compiled


def test_clear_cache(compiler: PatternCompiler) -> None:
    patterns = ["pattern1", "pattern2", "pattern3"]
    for pattern in patterns:
        compiler.compile_pattern(pattern)

    assert len(compiler._compiled_cache) == 3
    assert len(compiler._cache_order) == 3

    compiler.clear_cache()

    assert len(compiler._compiled_cache) == 0
    assert len(compiler._cache_order) == 0


def test_clear_cache_thread_safety(compiler: PatternCompiler) -> None:
    compiler.compile_pattern("pattern1")

    def compile_task() -> None:
        compiler.compile_pattern("pattern2")

    def clear_task() -> None:
        compiler.clear_cache()

    [compile_task(), clear_task()]

    assert len(compiler._compiled_cache) == len(compiler._cache_order)


def test_compile_pattern_handles_cache_race_between_outer_and_locked_check(
    compiler: PatternCompiler,
) -> None:
    pattern = r"race_me"
    cache_key = f"{hash(pattern)}:{re.IGNORECASE | re.MULTILINE}"
    compiler._compiled_cache[cache_key] = re.compile(pattern)
    compiler._cache_order.append(cache_key)

    real_lock = compiler._lock

    class _LockWrapper:
        def __enter__(self):
            compiler._compiled_cache.pop(cache_key, None)
            if cache_key in compiler._cache_order:
                compiler._cache_order.remove(cache_key)
            return real_lock.__enter__()

        def __exit__(self, *a):
            return real_lock.__exit__(*a)

    compiler._lock = _LockWrapper()
    compiled = compiler.compile_pattern(pattern)
    assert compiled.pattern == pattern
    compiler._lock = real_lock


def test_compile_pattern_returns_cached_entry_when_populated_during_lock_wait(
    compiler: PatternCompiler,
) -> None:
    pattern = r"populated_during_wait"
    cache_key = f"{hash(pattern)}:{re.IGNORECASE | re.MULTILINE}"
    pre_compiled = re.compile(pattern)

    real_lock = compiler._lock
    state = {"seen_outer": False}

    class _LockWrapper:
        def __enter__(self):
            if not state["seen_outer"]:
                state["seen_outer"] = True
                compiler._compiled_cache[cache_key] = pre_compiled
            return real_lock.__enter__()

        def __exit__(self, *a):
            return real_lock.__exit__(*a)

    compiler._lock = _LockWrapper()
    result = compiler.compile_pattern(pattern)
    assert result is pre_compiled
    compiler._lock = real_lock
