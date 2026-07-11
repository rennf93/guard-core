import re
import time
from typing import Any

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.detection_engine.compiler import (
    PatternCompiler,
    shared_regex_executor,
)
from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager


def test_shared_regex_executor_is_a_singleton() -> None:
    assert shared_regex_executor() is shared_regex_executor()


def test_safe_matcher_times_out_on_catastrophic_pattern() -> None:
    compiler = PatternCompiler()
    matcher = compiler.create_safe_matcher(r"(a+)+$", timeout=0.05)
    assert matcher("a" * 24 + "b") is None


def test_safe_matcher_still_works_after_a_timeout() -> None:
    compiler = PatternCompiler()
    slow = compiler.create_safe_matcher(r"(a+)+$", timeout=0.05)
    slow("a" * 24 + "b")
    fast = compiler.create_safe_matcher(r"abc")
    assert fast("xxabcxx") is not None


@pytest.fixture
def fresh_manager() -> Any:
    SusPatternsManager._instance = None
    manager = SusPatternsManager()
    manager.configure(SecurityConfig())
    yield manager
    SusPatternsManager._instance = None


def test_builtin_category_skips_safe_matcher(
    fresh_manager: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _fail(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("safe matcher used for built-in pattern")

    monkeypatch.setattr(fresh_manager._compiler, "create_safe_matcher", _fail)
    pattern = re.compile(r"<script", re.IGNORECASE)

    threat, timed_out = fresh_manager._check_regex_pattern(
        pattern, "<script>alert(1)</script>", "1.2.3.4", time.time(), "xss"
    )

    assert threat is not None
    assert timed_out is False


def test_custom_category_keeps_timeout_wrapper(
    fresh_manager: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    real = fresh_manager._compiler.create_safe_matcher

    def _tracking(pattern: str, timeout: float | None = None) -> Any:
        calls.append(pattern)
        return real(pattern, timeout)

    monkeypatch.setattr(fresh_manager._compiler, "create_safe_matcher", _tracking)
    pattern = re.compile(r"evil")

    threat, _ = fresh_manager._check_regex_pattern(
        pattern, "so evil", "1.2.3.4", time.time(), "custom"
    )

    assert threat is not None
    assert calls == ["evil"]


def test_custom_category_timeout_heuristic_ignores_wall_clock_jump(
    fresh_manager: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "guard_core.sync.handlers.suspatterns_handler.time.time", lambda: 5_000.0
    )
    monkeypatch.setattr(
        "guard_core.sync.handlers.suspatterns_handler.time.monotonic", lambda: 100.01
    )
    pattern_start = 100.0
    pattern = re.compile(r"zzz_never_matches_zzz")

    _, timed_out = fresh_manager._check_regex_pattern(
        pattern, "no match in here", "1.2.3.4", pattern_start, "custom"
    )

    assert timed_out is False
