import time

from guard_core.sync.detection_engine.compiler import PatternCompiler
from guard_core.sync.handlers.suspatterns_handler import (
    _PATTERN_SCAN_WINDOW_MATCHERS,
    _SCAN_WINDOW_PATTERNS,
    _WINDOWED_PATTERN_FINDERS,
    SusPatternsManager,
)

_LATENCY_CEILING_SECONDS = 4.0

_CATASTROPHIC_PATTERNS = [
    r"(?P<x>\d{1,3}\d{1,3})+$",
    r"((\d{1,3}\d{1,3}))+$",
    r"(?:(?:a|aa))+$",
    r"(?P<a>(?P<b>\d\d?))+$",
    r"(a+)+$",
    r"(\w+\s?)*$",
]


def _first_accepted_builtin_patterns(count: int) -> list[str]:
    excluded = set(_WINDOWED_PATTERN_FINDERS)
    excluded |= set(_PATTERN_SCAN_WINDOW_MATCHERS)
    excluded |= set(_SCAN_WINDOW_PATTERNS)
    accepted = [
        pattern
        for pattern, _ctx, _category in SusPatternsManager._pattern_definitions
        if pattern not in excluded
    ]
    return accepted[:count]


def test_catastrophic_patterns_are_rejected_well_under_the_old_forty_second_stall() -> (
    None
):
    compiler = PatternCompiler()
    for pattern in _CATASTROPHIC_PATTERNS:
        start = time.perf_counter()
        is_safe, _reason = compiler.validate_pattern_safety(pattern)
        elapsed = time.perf_counter() - start
        assert is_safe is False, f"{pattern!r} should have been rejected"
        assert elapsed < _LATENCY_CEILING_SECONDS, (
            f"{pattern!r} took {elapsed:.3f}s to reject, "
            f"expected under {_LATENCY_CEILING_SECONDS}s"
        )


def test_accepted_builtin_patterns_stay_accepted_and_validate_quickly() -> None:
    compiler = PatternCompiler()
    for pattern in _first_accepted_builtin_patterns(2):
        start = time.perf_counter()
        is_safe, reason = compiler.validate_pattern_safety(pattern)
        elapsed = time.perf_counter() - start
        assert is_safe is True, f"{pattern!r} should stay accepted, got: {reason}"
        assert elapsed < _LATENCY_CEILING_SECONDS, (
            f"{pattern!r} took {elapsed:.3f}s to validate, "
            f"expected under {_LATENCY_CEILING_SECONDS}s"
        )
