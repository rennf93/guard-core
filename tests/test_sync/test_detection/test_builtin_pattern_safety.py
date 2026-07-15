from guard_core.handlers.suspatterns_handler import (
    SusPatternsManager as AsyncSusPatternsManager,
)
from guard_core.sync.detection_engine.compiler import PatternCompiler
from guard_core.sync.handlers.suspatterns_handler import (
    _DEFAULT_MAX_SCAN_LENGTH,
    SusPatternsManager,
)


def test_sync_pattern_table_matches_async_pattern_table() -> None:
    assert (
        SusPatternsManager._pattern_definitions
        == AsyncSusPatternsManager._pattern_definitions
    )


def test_every_builtin_passes_the_safety_validator() -> None:
    pc = PatternCompiler()
    bad = []
    for pat, _c, cat in SusPatternsManager._pattern_definitions:
        ok, reason = pc.validate_pattern_safety(pat)
        if not ok:
            bad.append((cat, reason, pat))
    assert not bad, "built-ins that fail the ReDoS validator:\n" + "\n".join(
        f"  [{c}] {r} :: {p[:80]}" for c, r, p in bad
    )


def test_match_path_caps_input_length_in_legacy_mode() -> None:
    mgr = SusPatternsManager()
    mgr._preprocessor = None

    big = "A" * 5_000_000
    capped = mgr._preprocess_content(big, None)

    cap = getattr(mgr._config, "detection_max_content_length", _DEFAULT_MAX_SCAN_LENGTH)
    assert len(capped) == min(len(big), cap)
    assert len(capped) < len(big)
