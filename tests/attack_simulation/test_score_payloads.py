import json

import pytest

from tests.attack_simulation.score_payloads import main, score_payloads


@pytest.mark.asyncio
async def test_score_payloads_flags_malicious_and_benign():
    results = await score_payloads(
        ["<script>alert(1)</script>", "the quick brown fox jumps"]
    )
    assert [r["payload"] for r in results] == [
        "<script>alert(1)</script>",
        "the quick brown fox jumps",
    ]
    assert results[0]["detected"] is True
    assert results[1]["detected"] is False
    assert all(isinstance(r["threat_score"], float) for r in results)


def test_cli_round_trips(tmp_path):
    in_path = tmp_path / "in.json"
    out_path = tmp_path / "out.json"
    in_path.write_text(json.dumps(["<script>alert(1)</script>", "hello there"]))
    main([str(in_path), str(out_path)])
    results = json.loads(out_path.read_text())
    assert results[0]["detected"] is True
    assert results[1]["detected"] is False
