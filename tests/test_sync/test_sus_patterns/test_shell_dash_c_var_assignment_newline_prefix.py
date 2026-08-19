import multiprocessing as mp
import re
import time

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.suspatterns_handler import (
    _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE,
    sus_patterns_handler,
)
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_CONFIG = SecurityConfig()


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


def _text_body_request(body: str) -> SyncMockGuardRequest:
    encoded = body.encode()
    headers = {
        "content-length": str(len(encoded)),
        "content-type": "text/plain",
    }
    return SyncMockGuardRequest(body_content=encoded, headers=headers)


def _assert_body_fires_cmd_injection(body: str) -> None:
    request = _text_body_request(body)
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert "cmd_injection" in result.threat_categories


def _assert_body_does_not_fire(body: str) -> None:
    request = _text_body_request(body)
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is False


VAR_ASSIGNMENT_PREFIX_BODIES = [
    pytest.param("x%0AFOO=bar%20/bin/sh%20-c%20id", id="one_assignment"),
    pytest.param("x%0AA=1%20B=2%20/bin/sh%20-c%20id", id="two_assignments"),
    pytest.param(
        "x%0AA=1%20B=2%20C=3%20D=4%20E=5%20F=6%20G=7%20H=8%20/bin/sh%20-c%20id",
        id="eight_assignments",
    ),
]


@pytest.mark.parametrize("body", VAR_ASSIGNMENT_PREFIX_BODIES)
def test_var_assignment_newline_prefix_fires_cmd_injection(body: str) -> None:
    _assert_body_fires_cmd_injection(body)


EXISTING_B7_STILL_FIRES_BODIES = [
    pytest.param("x%0A/bin/sh%20-c%20id", id="arbitrary_prefix_bin_sh"),
    pytest.param("x" + chr(10) + "/bin/sh -c id", id="literal_newline_bin_sh"),
    pytest.param("x%0Aenv%20bash%20-c%20id", id="env_prefix_bash"),
]


@pytest.mark.parametrize("body", EXISTING_B7_STILL_FIRES_BODIES)
def test_b7_regression_bodies_still_fire(body: str) -> None:
    _assert_body_fires_cmd_injection(body)


def test_nine_assignments_prefix_not_detected_via_this_pattern() -> None:
    body = "x%0AA=1%20B=2%20C=3%20D=4%20E=5%20F=6%20G=7%20H=8%20I=9%20/bin/sh%20-c%20id"
    _assert_body_does_not_fire(body)


def _timed_search(pat: str, s: str, q: "mp.Queue[float]") -> None:
    compiled = re.compile(pat, re.IGNORECASE)
    t0 = time.time()
    compiled.search(s)
    q.put(time.time() - t0)


def _search_elapsed_seconds(pat: str, s: str, timeout: float) -> float | None:
    ctx = mp.get_context("forkserver")
    q: mp.Queue[float] = ctx.Queue()
    p = ctx.Process(target=_timed_search, args=(pat, s, q))
    p.start()
    p.join(timeout)
    if p.is_alive():
        p.terminate()
        p.join()
        return None
    return q.get() if not q.empty() else None


_ADVERSARIAL_VAR_ASSIGNMENT_NEWLINE_INPUT = "\nA=A " * 2000
_BOUNDED_VS_UNBOUNDED_LINEAR_TIME_CEILING_SECONDS = 0.2


def test_var_assignment_prefix_search_stays_under_linear_time_ceiling() -> None:
    elapsed = _search_elapsed_seconds(
        _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE,
        _ADVERSARIAL_VAR_ASSIGNMENT_NEWLINE_INPUT,
        timeout=5.0,
    )
    assert elapsed is not None, "regex search did not finish within the 5s timeout"
    assert elapsed < _BOUNDED_VS_UNBOUNDED_LINEAR_TIME_CEILING_SECONDS, (
        f"search took {elapsed:.3f}s on a 10000-char adversarial "
        f'"\\nA=A " * 2000 body, exceeding the '
        f"{_BOUNDED_VS_UNBOUNDED_LINEAR_TIME_CEILING_SECONDS}s ceiling measured "
        "to separate the bounded {0,8} var=val prefix (~0.005-0.01s measured) "
        "from an unbounded (?:...)* fragment (~0.8s measured), with margin for "
        "forkserver-child timing noise"
    )
