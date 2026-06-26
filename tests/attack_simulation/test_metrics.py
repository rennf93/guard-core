from tests.attack_simulation.metrics import Result, score


def _malicious(detected, attack_class, chain):
    return Result(True, detected, attack_class, chain, None)


def _benign(detected, category):
    return Result(False, detected, None, (), category)


def test_score_computes_rates_and_breakdowns():
    results = [
        _malicious(True, "xss", ()),
        _malicious(False, "xss", ("base64_wrap",)),
        _malicious(True, "sqli", ()),
        _benign(False, "encoded_legit"),
        _benign(True, "prose_sql_keywords"),
    ]
    out = score(results)
    assert out["totals"] == {
        "tp": 2,
        "fp": 1,
        "fn": 1,
        "tn": 1,
        "n_malicious": 3,
        "n_benign": 2,
    }
    assert out["detection_rate"] == 2 / 3
    assert out["fp_rate"] == 1 / 2
    assert out["per_class"]["xss"] == 0.5
    assert out["per_class"]["sqli"] == 1.0
    assert out["evasion_matrix"]["unmutated"] == 1.0
    assert out["evasion_matrix"]["base64_wrap"] == 0.0
    assert out["per_benign_category"]["prose_sql_keywords"] == 1.0
    assert out["per_benign_category"]["encoded_legit"] == 0.0


def test_score_handles_empty_groups():
    out = score([])
    assert out["detection_rate"] == 0.0
    assert out["fp_rate"] == 0.0
    assert out["f_score"] == 0.0
