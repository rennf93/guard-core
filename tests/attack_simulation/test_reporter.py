import json

from tests.attack_simulation.reporter import build_report, write_reports


def _metrics():
    return {
        "detection_rate": 0.9,
        "fp_rate": 0.2,
        "f_score": 0.84,
        "per_class": {"xss": 1.0, "sqli": 0.8},
        "evasion_matrix": {"unmutated": 1.0, "base64_wrap": 0.5},
        "per_benign_category": {"prose_sql_keywords": 0.6},
        "totals": {
            "tp": 9,
            "fp": 1,
            "fn": 1,
            "tn": 4,
            "n_malicious": 10,
            "n_benign": 5,
        },
    }


def test_build_report_merges_context():
    report = build_report(_metrics(), {"detection_compiler_timeout": 2.0}, 1.23, "abc")
    assert report["detection_rate"] == 0.9
    assert report["config"] == {"detection_compiler_timeout": 2.0}
    assert report["runtime_seconds"] == 1.23
    assert report["corpus_fingerprint"] == "abc"


def test_write_reports_emits_json_and_md(tmp_path):
    report = build_report(_metrics(), {"detection_compiler_timeout": 2.0}, 1.23, "abc")
    json_path, md_path = write_reports(report, tmp_path)
    loaded = json.loads(json_path.read_text())
    assert loaded["detection_rate"] == 0.9
    text = md_path.read_text()
    assert "Detection rate" in text
    assert "prose_sql_keywords" in text
    assert "base64_wrap" in text
