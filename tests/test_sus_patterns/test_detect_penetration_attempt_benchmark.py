import json
import time
from collections.abc import Iterator
from typing import NamedTuple
from urllib.parse import urlencode

import pytest

from guard_core.handlers.suspatterns_handler import (
    CATEGORY_CONTEXT_MAP,
    sus_patterns_handler,
)
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest
from tests.test_sus_patterns.test_detection_benchmark import (
    BENIGN_CORPUS,
    MALICIOUS_CORPUS,
)

_CONFIG = SecurityConfig()


@pytest.fixture(autouse=True)
def _force_legacy_detection_singleton() -> Iterator[None]:
    sus_patterns_handler._compiler = None
    sus_patterns_handler._preprocessor = None
    sus_patterns_handler._semantic_analyzer = None
    sus_patterns_handler._performance_monitor = None
    sus_patterns_handler._threat_score_threshold = 1.0
    yield


def _body_request(payload: str, content_type: str) -> MockGuardRequest:
    body = payload.encode()
    headers = {"content-length": str(len(body))}
    if content_type:
        headers["content-type"] = content_type
    return MockGuardRequest(body_content=body, headers=headers)


def _raw_body_request(payload: str) -> MockGuardRequest:
    return _body_request(payload, "")


def _form_body_request(payload: str) -> MockGuardRequest:
    return _body_request(
        urlencode({"field": payload}), "application/x-www-form-urlencoded"
    )


def _json_body_request(payload: str) -> MockGuardRequest:
    return _body_request(json.dumps({"outer": {"field": payload}}), "application/json")


def _multipart_body_request(payload: str) -> MockGuardRequest:
    boundary = "B0"
    part = f'Content-Disposition: form-data; name="field"\r\n\r\n{payload}'
    body = f"--{boundary}\r\n{part}\r\n--{boundary}--\r\n"
    return _body_request(body, f"multipart/form-data; boundary={boundary}")


def _header_request(payload: str) -> MockGuardRequest:
    return MockGuardRequest(headers={"x-e2e-probe": payload})


def _query_param_request(payload: str) -> MockGuardRequest:
    return MockGuardRequest(query_params={"q": payload})


def _url_path_request(payload: str) -> MockGuardRequest:
    return MockGuardRequest(path=payload)


_MECHANISM_BUILDERS = {
    "raw_body": _raw_body_request,
    "form_body": _form_body_request,
    "json_body_nested": _json_body_request,
    "multipart_body": _multipart_body_request,
    "header": _header_request,
    "query_param": _query_param_request,
    "url_path": _url_path_request,
}

_BODY_MECHANISMS = ("raw_body", "form_body", "json_body_nested", "multipart_body")
_ALL_MECHANISMS = (*_BODY_MECHANISMS, "header", "query_param", "url_path")
_CONTEXT_ONLY_MECHANISMS = {
    "header": "header",
    "query_param": "query_param",
    "url_path": "url_path",
}


def _valid_mechanisms_for_category(category: str) -> tuple[str, ...]:
    contexts = CATEGORY_CONTEXT_MAP[category]
    extra = tuple(
        mechanism
        for mechanism, context in _CONTEXT_ONLY_MECHANISMS.items()
        if context in contexts
    )
    return _BODY_MECHANISMS + extra


_PRODUCTION_MALICIOUS_CASES = [
    case for case in MALICIOUS_CORPUS if case.detector == "production"
]
_PRODUCTION_BENIGN_CASES = [
    case for case in BENIGN_CORPUS if case.detector == "production"
]


class TargetedCase(NamedTuple):
    case_id: str
    request: MockGuardRequest
    expect_detected: bool
    known_gap_reason: str = ""


_TARGETED_CASES: list[TargetedCase] = [
    TargetedCase(
        "embedded_probe_form_body_field_value",
        _body_request(
            "redirect=/wp-admin/install.php&ok=1",
            "application/x-www-form-urlencoded",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_nested_json_body",
        _body_request(
            '{"data":{"redirect_url":"/wp-admin/install.php"}}',
            "application/json",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_body",
        _body_request(
            "Note: the scanner hit /wp-admin/install.php on our staging.",
            "text/plain",
        ),
        False,
        "prose is scanned as one blob against the whole-content-anchored "
        "cms_probing pattern; a full sentence around the path never matches "
        "it, and matching a path substring anywhere in prose is exactly the "
        "false-positive shape defect 1 removed (2/2 measured benign URL-"
        "quoting sentences false-positived when that alternative existed), "
        "so this stays a documented gap",
    ),
]


async def _mechanism_for_index(mechanisms: tuple[str, ...], index: int) -> str:
    return mechanisms[index % len(mechanisms)]


async def _detected_via(mechanism: str, payload: str) -> bool:
    request = _MECHANISM_BUILDERS[mechanism](payload)
    result = await detect_penetration_attempt(request, _CONFIG)
    return result.is_threat


def _fraction(numerator: int, denominator: int) -> str:
    percentage = 100.0 * numerator / denominator if denominator else 0.0
    return f"{numerator}/{denominator} ({percentage:.1f}%)"


_KNOWN_E2E_FALSE_POSITIVES: dict[str, str] = {
    "sensitive_file_json_payload_ending_source_path": (
        "raw_body with no content-type and a JSON-shaped payload is "
        "auto-sniffed and scanned field by field; the isolated 'path' field "
        "value '/opt/app/worker.py' fully matches the whole-string-anchored "
        "source-extension pattern that only ever sees the value, never the "
        "surrounding JSON key. Pre-existing in the unmodified code "
        "(reproduced against HEAD before this change); unrelated to defects "
        "1-3 and 5, so left as a documented gap rather than reworking the "
        "shared sensitive_file pattern under this change"
    ),
}

BASELINE_MALICIOUS_DETECTED_TOTAL = 157


@pytest.mark.asyncio
async def test_detect_penetration_attempt_recall_and_false_positive_rate() -> None:
    assert len(_PRODUCTION_MALICIOUS_CASES) >= 100
    assert len(_PRODUCTION_BENIGN_CASES) >= 100

    start = time.monotonic()

    mechanisms_exercised: set[str] = set()
    malicious_detected = 0
    undetected_case_ids: list[str] = []
    detected_by_mechanism: dict[str, int] = {}
    total_by_mechanism: dict[str, int] = {}
    for index, case in enumerate(_PRODUCTION_MALICIOUS_CASES):
        mechanism = await _mechanism_for_index(
            _valid_mechanisms_for_category(case.category), index
        )
        mechanisms_exercised.add(mechanism)
        total_by_mechanism[mechanism] = total_by_mechanism.get(mechanism, 0) + 1
        if await _detected_via(mechanism, case.payload):
            malicious_detected += 1
            detected_by_mechanism[mechanism] = (
                detected_by_mechanism.get(mechanism, 0) + 1
            )
        else:
            undetected_case_ids.append(f"{case.case_id}[{mechanism}]")

    benign_flagged = 0
    known_false_positive_case_ids: list[str] = []
    unexpected_false_positive_case_ids: list[str] = []
    for index, benign_case in enumerate(_PRODUCTION_BENIGN_CASES):
        mechanism = await _mechanism_for_index(_ALL_MECHANISMS, index)
        mechanisms_exercised.add(mechanism)
        if await _detected_via(mechanism, benign_case.payload):
            benign_flagged += 1
            if benign_case.case_id in _KNOWN_E2E_FALSE_POSITIVES:
                known_false_positive_case_ids.append(
                    f"{benign_case.case_id}[{mechanism}]"
                )
            else:
                unexpected_false_positive_case_ids.append(
                    f"{benign_case.case_id}[{mechanism}]"
                )

    targeted_failures: list[str] = []
    for targeted in _TARGETED_CASES:
        result = await detect_penetration_attempt(targeted.request, _CONFIG)
        if result.is_threat != targeted.expect_detected:
            targeted_failures.append(targeted.case_id)

    wall_time_seconds = time.monotonic() - start

    report_lines = [
        "END-TO-END DETECTION BENCHMARK REPORT (detect_penetration_attempt)",
        f"malicious corpus: {len(_PRODUCTION_MALICIOUS_CASES)} cases "
        f"({len(MALICIOUS_CORPUS) - len(_PRODUCTION_MALICIOUS_CASES)} "
        "encoding-only cases excluded: the shared production singleton runs "
        "without a preprocessor by default)",
        f"benign corpus: {len(_PRODUCTION_BENIGN_CASES)} cases",
        f"mechanisms exercised: {sorted(mechanisms_exercised)}",
        f"wall time: {wall_time_seconds:.3f}s",
        "",
        "recall by delivery mechanism (detected/total):",
    ]
    for mechanism in _ALL_MECHANISMS:
        total = total_by_mechanism.get(mechanism, 0)
        if total:
            report_lines.append(
                f"  {mechanism:16} "
                f"{_fraction(detected_by_mechanism.get(mechanism, 0), total)}"
            )
    report_lines.extend(
        [
            "",
            f"total recall:  "
            f"{_fraction(malicious_detected, len(_PRODUCTION_MALICIOUS_CASES))}",
            f"total fp rate: "
            f"{_fraction(benign_flagged, len(_PRODUCTION_BENIGN_CASES))}",
            "",
            "targeted embedded-probe cases (defect 5):",
        ]
    )
    for targeted in _TARGETED_CASES:
        report_lines.append(
            f"  {targeted.case_id}: expected={targeted.expect_detected} "
            f"gap={targeted.known_gap_reason or 'none'}"
        )
    report_lines.append("")
    report_lines.append("known end-to-end false positives (documented, still counted):")
    for case_id, reason in _KNOWN_E2E_FALSE_POSITIVES.items():
        report_lines.append(f"  {case_id}: {reason}")
    report = "\n".join(report_lines)
    print(report)

    assert not targeted_failures, f"{targeted_failures}\n{report}"

    assert malicious_detected >= BASELINE_MALICIOUS_DETECTED_TOTAL, (
        f"overall recall regressed: baseline={BASELINE_MALICIOUS_DETECTED_TOTAL} "
        f"actual={malicious_detected} newly_undetected={undetected_case_ids}\n"
        f"{report}"
    )
    assert not unexpected_false_positive_case_ids, (
        f"unexpected false positives: {unexpected_false_positive_case_ids}\n{report}"
    )
    assert benign_flagged <= len(_KNOWN_E2E_FALSE_POSITIVES), (
        f"more benign cases flagged than documented known false positives: "
        f"actual={benign_flagged} known={known_false_positive_case_ids}\n{report}"
    )
