import re
import time
from collections.abc import Callable
from unittest.mock import patch

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.detection_engine.compiler import (
    PatternCompiler,
    _detect_nested_unbounded_quantifier,
    _extract_literal_chars,
    _find_group_end,
    _split_top_level_alternations,
    _strip_escapes_and_char_classes,
)
from guard_core.sync.handlers.suspatterns_handler import (
    _WINDOWED_PATTERN_FINDERS,
    SusPatternsManager,
    sus_patterns_handler,
)

_CONFIG = SecurityConfig(detection_compiler_timeout=2.0)
_BENIGN_MATCHING_PAYLOAD = "<script>alert(1)</script>"
_CUSTOM_MARKER = "zzq_custom_hardening_marker_zzq"
_CUSTOM_PATTERN = rf"{_CUSTOM_MARKER}\d+"


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig(detection_compiler_timeout=2.0))
    sus_patterns_handler.compiled_custom_patterns = set()
    sus_patterns_handler.custom_patterns = set()


def test_overlapping_equal_literal_branches_flagged() -> None:
    assert _detect_nested_unbounded_quantifier(r"(b|b)*c") is not None
    assert _detect_nested_unbounded_quantifier(r"(q|q)*r") is not None


def test_overlapping_prefix_literal_branches_flagged() -> None:
    assert _detect_nested_unbounded_quantifier(r"(X|XY)*") is not None
    assert _detect_nested_unbounded_quantifier(r"(a|ab)*") is not None
    assert _detect_nested_unbounded_quantifier(r"(ab|abc)*") is not None


def test_disjoint_literal_branches_not_flagged() -> None:
    assert _detect_nested_unbounded_quantifier(r"(a|b)*") is None
    assert _detect_nested_unbounded_quantifier(r"(http|https)") is None
    assert _detect_nested_unbounded_quantifier(r"(?:[/\\][\w.\-~%]*)*") is None
    assert _detect_nested_unbounded_quantifier(r"(?:[\w.\-~%]+[/\\])*") is None
    assert _detect_nested_unbounded_quantifier(r"(a{2,4})*") is None


def test_char_class_overlap_branches_not_flagged() -> None:
    assert _detect_nested_unbounded_quantifier(r"(\w|\w)*x") is None
    assert _detect_nested_unbounded_quantifier(r"([^`\\n]|\\.)*") is None
    assert _detect_nested_unbounded_quantifier(r"([\w]|x)*") is None
    assert _detect_nested_unbounded_quantifier(r"([ab]|x)*") is None


def test_escape_inside_group_not_flagged() -> None:
    assert _detect_nested_unbounded_quantifier(r"(\.)+") is None
    assert _detect_nested_unbounded_quantifier(r"(\()") is None


def test_find_group_end_handles_unterminated_char_class() -> None:
    assert _find_group_end("(a[)*", 0) is None
    assert _detect_nested_unbounded_quantifier(r"(a[)*") is None


def test_strip_escapes_and_char_classes_handles_malformed() -> None:
    assert _strip_escapes_and_char_classes("abc[") == "abcX"
    assert _strip_escapes_and_char_classes("abc\\") == "abc\\"


def test_validate_pattern_safety_rejects_overlapping_alternation() -> None:
    compiler = PatternCompiler()
    for pattern in [r"(b|b)*c", r"(q|q)*r", r"(X|XY)*", r"(a|ab)*"]:
        is_safe, reason = compiler.validate_pattern_safety(pattern)
        assert is_safe is False, f"{pattern} was not rejected"
        assert "nested unbounded quantifier" in reason.lower()


def test_extract_literal_chars_pulls_trigger_char() -> None:
    assert "b" in _extract_literal_chars(r"(b|b)*c")
    assert "q" in _extract_literal_chars(r"(q|q)*r")
    assert "X" in _extract_literal_chars(r"(X|XY)*")


def test_extract_literal_chars_skips_char_classes_with_escapes() -> None:
    chars = _extract_literal_chars(r"[\w]abc")
    assert chars == ["a", "b", "c"]
    assert _extract_literal_chars(r"[\d\-]+") == []
    assert _extract_literal_chars(r"abc[") == ["a", "b", "c"]


def test_split_top_level_alternations_handles_malformed() -> None:
    assert _split_top_level_alternations("a|b") == ["a", "b"]
    assert _split_top_level_alternations("a[") == ["a["]
    assert _split_top_level_alternations(r"\|") == [r"\|"]
    assert _split_top_level_alternations("(a|b)|c") == ["(a|b)", "c"]


def test_validate_pattern_safety_probes_pattern_derived_alphabet() -> None:
    compiler = PatternCompiler()
    probed: list[str] = []

    class _RecordingCompiled:
        def search(self, text: str) -> re.Match | None:
            probed.append(text)
            return None

    with patch.object(
        PatternCompiler,
        "compile_pattern_sync",
        lambda self, p, flags=0: _RecordingCompiled(),
    ):
        compiler.validate_pattern_safety(r"bbb")

    b_probed = [t for t in probed if t and len(t) >= 10 and all(ch == "b" for ch in t)]
    assert b_probed, f"pattern-derived b-strings were not probed: {probed[:6]}"


def test_validator_rejects_zero_built_in_patterns() -> None:
    compiler = PatternCompiler()
    rejected = []
    for pattern, _ctx, _category in SusPatternsManager._pattern_definitions:
        if pattern in _WINDOWED_PATTERN_FINDERS:
            continue
        is_safe, _reason = compiler.validate_pattern_safety(pattern)
        if not is_safe:
            rejected.append(pattern)
    assert rejected == []


def test_windowed_patterns_are_exactly_the_scan_window_converted_four() -> None:
    assert len(_WINDOWED_PATTERN_FINDERS) == 4
    windowed_pattern_sources = set(_WINDOWED_PATTERN_FINDERS)
    builtin_pattern_sources = {
        pattern for pattern, _ctx, _category in SusPatternsManager._pattern_definitions
    }
    assert windowed_pattern_sources <= builtin_pattern_sources


def test_validator_keeps_benign_custom_corpus_safe() -> None:
    compiler = PatternCompiler()
    benign_custom = [
        r"foo.*bar",
        r"attackterm\d+",
        r"<custom>\w+</custom>",
        r"https?://example\.com",
        r"\bword\b",
        r"(a|b)",
    ]
    rejected = []
    for pattern in benign_custom:
        is_safe, _reason = compiler.validate_pattern_safety(pattern)
        if not is_safe:
            rejected.append(pattern)
    assert rejected == [], f"benign custom patterns falsely rejected: {rejected}"


def test_overlapping_alternation_pattern_rejected_at_registration() -> None:
    ok = SusPatternsManager.add_pattern(r"(b|b)*c", custom=True)
    assert ok is False
    assert r"(b|b)*c" not in sus_patterns_handler.custom_patterns


def test_custom_pattern_routed_through_pool_path() -> None:
    SusPatternsManager.add_pattern(_CUSTOM_PATTERN, custom=True)

    captured: list[bool] = []
    original = PatternCompiler.create_async_safe_finditer_matcher

    def _spy(
        self: PatternCompiler,
        pattern: str | re.Pattern,
        timeout: float | None = None,
        inline_safe: bool = False,
    ) -> Callable[[str], list[re.Match]]:
        captured.append(inline_safe)
        return original(self, pattern, timeout=timeout, inline_safe=inline_safe)

    with patch.object(PatternCompiler, "create_async_safe_finditer_matcher", _spy):
        result = sus_patterns_handler.detect(
            f"{_CUSTOM_MARKER}12345", "1.2.3.4", "request_body"
        )

    assert result["is_threat"] is True
    assert captured.count(False) >= 1


def test_built_in_pattern_routed_through_inline_safe_path() -> None:
    captured: list[bool] = []
    original = PatternCompiler.create_async_safe_finditer_matcher

    def _spy(
        self: PatternCompiler,
        pattern: str | re.Pattern,
        timeout: float | None = None,
        inline_safe: bool = False,
    ) -> Callable[[str], list[re.Match]]:
        captured.append(inline_safe)
        return original(self, pattern, timeout=timeout, inline_safe=inline_safe)

    with patch.object(PatternCompiler, "create_async_safe_finditer_matcher", _spy):
        result = sus_patterns_handler.detect(
            _BENIGN_MATCHING_PAYLOAD, "1.2.3.4", "request_body"
        )

    assert result["is_threat"] is True
    assert captured.count(True) >= 1


def test_built_in_detect_is_fast_and_non_blocking() -> None:
    start = time.monotonic()
    result = sus_patterns_handler.detect(
        _BENIGN_MATCHING_PAYLOAD, "1.2.3.4", "request_body"
    )
    elapsed = time.monotonic() - start

    assert result["is_threat"] is True
    assert elapsed < 2.0
