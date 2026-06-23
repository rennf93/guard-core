import re
import threading
import types
from typing import cast

import pytest

from guard_core.sync.detection_engine.compiler import PatternCompiler


def test_distinct_patterns_get_distinct_cache_entries() -> None:
    compiler = PatternCompiler()

    p1 = compiler.compile_pattern("alpha", re.IGNORECASE)
    p2 = compiler.compile_pattern("beta", re.IGNORECASE)

    assert p1.pattern == "alpha"
    assert p2.pattern == "beta"
    assert len(compiler._compiled_cache) == 2


def test_cache_key_is_deterministic_pattern_flags_form() -> None:
    compiler = PatternCompiler()
    compiler.compile_pattern("xyz", 0)
    keys = list(compiler._compiled_cache.keys())
    assert keys == ["xyz:0"], (
        f"cache key must be deterministic 'pattern:flags', got {keys!r}"
    )


def test_same_pattern_same_flags_hits_cache() -> None:
    compiler = PatternCompiler()
    p1 = compiler.compile_pattern("repeat", re.IGNORECASE)
    p2 = compiler.compile_pattern("repeat", re.IGNORECASE)
    assert p1 is p2
    assert len(compiler._compiled_cache) == 1


def test_same_pattern_different_flags_creates_separate_entries() -> None:
    compiler = PatternCompiler()
    p_ci = compiler.compile_pattern("Word", re.IGNORECASE)
    p_cs = compiler.compile_pattern("Word", 0)
    assert p_ci is not p_cs
    assert len(compiler._compiled_cache) == 2


def test_cache_eviction_when_full() -> None:
    compiler = PatternCompiler(max_cache_size=2)
    compiler.compile_pattern("first", 0)
    compiler.compile_pattern("second", 0)
    compiler.compile_pattern("third", 0)
    assert len(compiler._compiled_cache) == 2
    assert "first:0" not in compiler._compiled_cache


def test_cache_hit_lru_reorder() -> None:
    compiler = PatternCompiler()
    compiler.compile_pattern("cached", 0)
    compiler.compile_pattern("cached", 0)
    assert len(compiler._compiled_cache) == 1


def test_compile_pattern_sync() -> None:
    compiler = PatternCompiler()
    result = compiler.compile_pattern_sync("hello", re.IGNORECASE)
    assert isinstance(result, re.Pattern)
    assert result.pattern == "hello"


def test_validate_pattern_safety_safe_pattern() -> None:
    compiler = PatternCompiler()
    safe, msg = compiler.validate_pattern_safety("hello world")
    assert safe is True
    assert msg == "Pattern appears safe"


def test_validate_pattern_safety_dangerous_pattern() -> None:
    compiler = PatternCompiler()
    safe, msg = compiler.validate_pattern_safety(r"(.*)+")
    assert safe is False
    assert "dangerous construct" in msg


def test_validate_pattern_safety_custom_test_strings() -> None:
    compiler = PatternCompiler()
    safe, msg = compiler.validate_pattern_safety("test", test_strings=["abc", "xyz"])
    assert safe is True


def test_validate_pattern_safety_invalid_regex() -> None:
    compiler = PatternCompiler()
    safe, msg = compiler.validate_pattern_safety("[invalid")
    assert safe is False
    assert "Pattern validation failed" in msg


def test_validate_pattern_safety_elapsed_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import time as time_mod

    call_count = 0

    def fake_time() -> float:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return 0.0
        return 1.0

    monkeypatch.setattr(time_mod, "time", fake_time)
    compiler = PatternCompiler()
    safe, msg = compiler.validate_pattern_safety("safe", test_strings=["x"])
    assert safe is False
    assert "timed out" in msg


def test_validate_pattern_safety_concurrent_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import concurrent.futures

    class FakeExecutor:
        def __enter__(self) -> "FakeExecutor":
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def submit(self, _fn: object) -> "FakeFuture":
            return FakeFuture()

    class FakeFuture:
        def result(self, timeout: float = 0) -> None:
            raise concurrent.futures.TimeoutError()

    monkeypatch.setattr(
        concurrent.futures, "ThreadPoolExecutor", lambda **kw: FakeExecutor()
    )
    compiler = PatternCompiler()
    safe, msg = compiler.validate_pattern_safety("safe", test_strings=["x"])
    assert safe is False
    assert "timed out" in msg


def test_create_safe_matcher_returns_match() -> None:
    compiler = PatternCompiler()
    matcher = compiler.create_safe_matcher("hello")
    result = matcher("say hello world")
    assert result is not None


def test_create_safe_matcher_no_match_returns_none() -> None:
    compiler = PatternCompiler()
    matcher = compiler.create_safe_matcher("nomatch")
    result = matcher("completely unrelated")
    assert result is None


def test_create_safe_matcher_timeout_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import concurrent.futures

    class FakeExecutor:
        def __enter__(self) -> "FakeExecutor":
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def submit(self, _fn: object) -> "FakeFuture":
            return FakeFuture()

    class FakeFuture:
        def result(self, timeout: float = 0) -> None:
            raise concurrent.futures.TimeoutError()

        def cancel(self) -> None:
            pass

    monkeypatch.setattr(
        concurrent.futures, "ThreadPoolExecutor", lambda **kw: FakeExecutor()
    )
    compiler = PatternCompiler()
    matcher = compiler.create_safe_matcher("x")
    result = matcher("test")
    assert result is None


def test_create_safe_matcher_exception_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import concurrent.futures

    class FakeExecutor:
        def __enter__(self) -> "FakeExecutor":
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def submit(self, _fn: object) -> "FakeFuture":
            return FakeFuture()

    class FakeFuture:
        def result(self, timeout: float = 0) -> None:
            raise RuntimeError("boom")

    monkeypatch.setattr(
        concurrent.futures, "ThreadPoolExecutor", lambda **kw: FakeExecutor()
    )
    compiler = PatternCompiler()
    matcher = compiler.create_safe_matcher("x")
    result = matcher("test")
    assert result is None


def test_create_safe_matcher_uses_default_timeout() -> None:
    compiler = PatternCompiler(default_timeout=1.0)
    matcher = compiler.create_safe_matcher("hi")
    result = matcher("hi there")
    assert result is not None


def test_batch_compile_with_validation() -> None:
    compiler = PatternCompiler()
    result = compiler.batch_compile(["hello", "world"], validate=True)
    assert "hello" in result
    assert "world" in result


def test_batch_compile_without_validation() -> None:
    compiler = PatternCompiler()
    result = compiler.batch_compile(["hello"], validate=False)
    assert "hello" in result


def test_batch_compile_skips_dangerous_patterns() -> None:
    compiler = PatternCompiler()
    result = compiler.batch_compile([r"(.*)+", "safe"], validate=True)
    assert r"(.*)+'" not in result
    assert "safe" in result


def test_batch_compile_skips_invalid_regex() -> None:
    compiler = PatternCompiler()
    result = compiler.batch_compile(["[invalid", "valid"], validate=False)
    assert "[invalid" not in result
    assert "valid" in result


def test_clear_cache() -> None:
    compiler = PatternCompiler()
    compiler.compile_pattern("a", 0)
    compiler.compile_pattern("b", 0)
    assert len(compiler._compiled_cache) == 2
    compiler.clear_cache()
    assert len(compiler._compiled_cache) == 0
    assert len(compiler._cache_order) == 0


def test_compile_pattern_cache_hit_then_evicted_branch() -> None:
    compiler = PatternCompiler()
    compiler.compile_pattern("evict_me", 0)

    original_lock = compiler._lock

    class EvictOnFirstAcquire:
        _call_count = 0

        def __enter__(self) -> "EvictOnFirstAcquire":
            self._call_count += 1
            if self._call_count == 1:
                compiler._compiled_cache.clear()
                compiler._cache_order.clear()
            original_lock.__enter__()
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc_val: BaseException | None,
            exc_tb: types.TracebackType | None,
        ) -> None:
            original_lock.__exit__(exc_type, exc_val, exc_tb)

    compiler._lock = cast(threading.Lock, EvictOnFirstAcquire())
    result = compiler.compile_pattern("evict_me", 0)
    assert result.pattern == "evict_me"


def test_compile_pattern_concurrent_write_branch() -> None:
    compiler = PatternCompiler()

    original_lock = compiler._lock

    class InsertOnFirstAcquire:
        _call_count = 0

        def __enter__(self) -> "InsertOnFirstAcquire":
            self._call_count += 1
            if self._call_count == 1:
                key = "concurrent:0"
                compiler._compiled_cache[key] = re.compile("concurrent", 0)
                compiler._cache_order.append(key)
            original_lock.__enter__()
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc_val: BaseException | None,
            exc_tb: types.TracebackType | None,
        ) -> None:
            original_lock.__exit__(exc_type, exc_val, exc_tb)

    compiler._lock = cast(threading.Lock, InsertOnFirstAcquire())
    result = compiler.compile_pattern("concurrent", 0)
    assert result.pattern == "concurrent"
