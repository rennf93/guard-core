import re

import pytest

from guard_core.handlers.suspatterns_handler import (
    SusPatternsManager as AsyncSusPatternsManager,
)
from guard_core.sync.detection_engine.compiler import PatternCompiler
from guard_core.sync.handlers.suspatterns_handler import (
    _DEFAULT_MAX_SCAN_LENGTH,
    _KNOWN_QUADRATIC_BUILTIN_PATTERNS_PENDING_B_XQ_FIX,
    _MEASUREMENT_BORDERLINE_BUILTIN_PATTERNS,
    _PATTERN_SCAN_WINDOW_MATCHERS,
    _SCAN_WINDOW_PATTERNS,
    _WINDOWED_PATTERN_FINDERS,
    SusPatternsManager,
)


def test_sync_pattern_table_matches_async_pattern_table() -> None:
    assert (
        SusPatternsManager._pattern_definitions
        == AsyncSusPatternsManager._pattern_definitions
    )


@pytest.mark.redos_timing
def test_every_builtin_not_in_the_known_quadratic_set_passes_the_safety_validator() -> (
    None
):
    pc = PatternCompiler()
    bad = []
    for pat, _c, cat in SusPatternsManager._pattern_definitions:
        if (
            pat in _WINDOWED_PATTERN_FINDERS
            or pat in _PATTERN_SCAN_WINDOW_MATCHERS
            or pat in _SCAN_WINDOW_PATTERNS
        ):
            continue
        if (
            pat in _KNOWN_QUADRATIC_BUILTIN_PATTERNS_PENDING_B_XQ_FIX
            or pat in _MEASUREMENT_BORDERLINE_BUILTIN_PATTERNS
        ):
            continue
        ok, reason = pc.validate_pattern_safety(pat)
        if not ok:
            bad.append((cat, reason, pat))
    assert not bad, "built-ins that fail the ReDoS validator:\n" + "\n".join(
        f"  [{c}] {r} :: {p[:80]}" for c, r, p in bad
    )


def test_match_path_caps_input_length_in_legacy_mode() -> None:
    mgr = SusPatternsManager()
    original_preprocessor = mgr._preprocessor
    mgr._preprocessor = None

    try:
        big = "A" * 5_000_000
        capped, decode_budget_exhausted = mgr._preprocess_content(big, None)

        cap = getattr(
            mgr._config, "detection_max_content_length", _DEFAULT_MAX_SCAN_LENGTH
        )
        assert len(capped) == min(len(big), cap)
        assert len(capped) < len(big)
        assert decode_budget_exhausted is False
    finally:
        mgr._preprocessor = original_preprocessor


def test_builtin_patterns_compile_without_multiline() -> None:
    manager = SusPatternsManager()
    for compiled, _contexts, _category in manager.compiled_patterns:
        assert not compiled.flags & re.MULTILINE, compiled.pattern[:60]


def test_custom_patterns_keep_multiline_for_compatibility() -> None:
    manager = SusPatternsManager()
    manager.add_pattern(r"line-anchored-custom-token$", custom=True)
    try:
        custom_compiled = [
            compiled
            for compiled, _contexts, category in manager.compiled_custom_patterns
            if category == "custom"
        ]
        assert custom_compiled
        assert all(c.flags & re.MULTILINE for c in custom_compiled)
    finally:
        manager.remove_pattern(r"line-anchored-custom-token$", custom=True)
