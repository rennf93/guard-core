from guard_core.detection_result import DetectionResult


def test_detection_result_creation_all_fields() -> None:
    result = DetectionResult(
        is_threat=True,
        trigger_info="Query param 'q': XSS pattern",
        threat_categories=["xss"],
        threat_scores={"xss": 0.85},
    )
    assert result.is_threat is True
    assert result.trigger_info == "Query param 'q': XSS pattern"
    assert result.threat_categories == ["xss"]
    assert result.threat_scores == {"xss": 0.85}


def test_detection_result_defaults_for_empty_threat() -> None:
    result = DetectionResult(is_threat=False, trigger_info="not_enabled")
    assert result.is_threat is False
    assert result.trigger_info == "not_enabled"
    assert result.threat_categories == []
    assert result.threat_scores == {}


def test_detection_result_empty_threat_categories_is_fresh_list() -> None:
    a = DetectionResult(is_threat=False, trigger_info="")
    b = DetectionResult(is_threat=False, trigger_info="")
    a.threat_categories.append("xss")
    assert b.threat_categories == []


def test_detection_result_empty_threat_scores_is_fresh_dict() -> None:
    a = DetectionResult(is_threat=False, trigger_info="")
    b = DetectionResult(is_threat=False, trigger_info="")
    a.threat_scores["xss"] = 0.5
    assert b.threat_scores == {}
