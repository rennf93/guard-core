from unittest.mock import patch

import pytest

from guard_core.detection_engine.preprocessor import ContentPreprocessor

_PAYLOAD = "uid=admin' OR '1'='1"


def _between_window_midpoints(body_size: int, max_content_length: int) -> list[int]:
    nw = 11
    wsize = max(1, max_content_length // nw)
    last_start = body_size - wsize
    stride = last_start / (nw - 1)
    starts = [round(stride * i) for i in range(nw)]
    return [(starts[i] + starts[i + 1]) // 2 for i in range(nw - 1)]


def _body_with_payload_at(body_size: int, offset: int, payload: str) -> str:
    body = list("A" * body_size)
    for j, ch in enumerate(payload):
        if offset + j < body_size:
            body[offset + j] = ch
    return "".join(body)


@pytest.mark.parametrize("body_size", [110_000, 200_000, 256_000])
def test_full_scan_retains_payload_at_every_between_window_midpoint(
    body_size: int,
) -> None:
    pp = ContentPreprocessor(max_content_length=10000, preserve_attack_patterns=True)

    for offset in _between_window_midpoints(body_size, pp.max_content_length):
        body = _body_with_payload_at(body_size, offset, _PAYLOAD)
        sampled = pp.truncate_safely(body)
        assert _PAYLOAD in sampled, (
            f"payload at offset {offset} lost from full-scan sample "
            f"(sampled_len={len(sampled)})"
        )


def test_full_scan_returns_whole_body_up_to_cap() -> None:
    pp = ContentPreprocessor(max_content_length=10000, preserve_attack_patterns=True)
    body = "A" * pp._MAX_FULL_SCAN_BYTES
    assert pp.truncate_safely(body) == body


def test_full_scan_caps_body_above_cap_with_tail_represented() -> None:
    pp = ContentPreprocessor(max_content_length=10000, preserve_attack_patterns=True)
    body = "A" * (pp._MAX_FULL_SCAN_BYTES + 5000)
    result = pp.truncate_safely(body)
    assert len(result) == pp._MAX_FULL_SCAN_BYTES
    assert result == pp._cap_with_tail(body)


def test_full_scan_cap_preserves_tail_payload_when_head_has_no_indicators() -> None:
    pp = ContentPreprocessor(max_content_length=10000, preserve_attack_patterns=True)
    tail_payload = "; cat /etc/passwd"
    body = "A" * (pp._MAX_FULL_SCAN_BYTES - len(tail_payload) + 100) + tail_payload
    result = pp.truncate_safely(body)
    assert tail_payload in result


def test_full_scan_preserve_disabled_blind_truncates_to_full_scan_cap() -> None:
    pp = ContentPreprocessor(max_content_length=10000, preserve_attack_patterns=False)
    body = "<script>x</script>" + "A" * (pp._MAX_FULL_SCAN_BYTES + 100)
    result = pp.truncate_safely(body)
    assert len(result) == pp._MAX_FULL_SCAN_BYTES
    assert result == body[: pp._MAX_FULL_SCAN_BYTES]


def test_full_scan_above_cap_with_attack_regions_exceeding_budget_concatenates() -> (
    None
):
    pp = ContentPreprocessor(max_content_length=10000, preserve_attack_patterns=True)
    body = "A" * (pp._MAX_FULL_SCAN_BYTES + 100)
    big_region = (0, pp._MAX_FULL_SCAN_BYTES + 50)
    with patch.object(pp, "extract_attack_regions", return_value=[big_region]):
        result = pp.truncate_safely(body)
    assert len(result) == pp._MAX_FULL_SCAN_BYTES
    assert result == body[: pp._MAX_FULL_SCAN_BYTES]


def test_extract_and_concatenate_breaks_when_first_region_drains_budget() -> None:
    pp = ContentPreprocessor(max_content_length=10000, preserve_attack_patterns=True)
    out = pp._extract_and_concatenate_attack_regions(
        "AAAAABBBBB", [(0, 5), (5, 10)], budget=3
    )
    assert out == "AAA"


def test_full_scan_cap_defaults_to_262144_when_unset() -> None:
    pp = ContentPreprocessor(max_content_length=10000, preserve_attack_patterns=True)
    assert pp._MAX_FULL_SCAN_BYTES == 262144


def test_full_scan_cap_follows_constructor_override() -> None:
    pp = ContentPreprocessor(
        max_content_length=10000,
        preserve_attack_patterns=True,
        max_full_scan_bytes=1_000_000,
    )
    assert pp._MAX_FULL_SCAN_BYTES == 1_000_000
    body = "A" * 1_000_000
    assert pp.truncate_safely(body) == body


def test_full_scan_cap_override_extends_mid_body_detection_past_default() -> None:
    pp = ContentPreprocessor(
        max_content_length=10000,
        preserve_attack_patterns=True,
        max_full_scan_bytes=1_000_000,
    )
    payload = "; cat /etc/passwd"
    offset = 300_000
    body = _body_with_payload_at(600_000, offset, payload)
    result = pp.truncate_safely(body)
    assert result == body


def test_full_scan_cap_below_tail_bytes_still_caps_at_configured_size() -> None:
    pp = ContentPreprocessor(
        max_content_length=100,
        preserve_attack_patterns=True,
        max_full_scan_bytes=1024,
    )
    body = "A" * 5000
    result = pp._cap_with_tail(body)
    assert len(result) == 1024
    assert result == body[-1024:]
