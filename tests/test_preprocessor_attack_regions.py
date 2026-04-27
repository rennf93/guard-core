import pytest

from guard_core.detection_engine.preprocessor import ContentPreprocessor


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
