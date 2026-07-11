import multiprocessing as mp
import re
import time
from collections.abc import Callable

import pytest

from guard_core.detection_engine.compiler import PatternCompiler
from guard_core.handlers.suspatterns_handler import SusPatternsManager

mp.set_start_method("fork", force=True)
IM = re.IGNORECASE | re.MULTILINE


def _child(pat: str, text: str, q: mp.Queue) -> None:
    t0 = time.time()
    re.compile(pat, IM).search(text)
    q.put(time.time() - t0)


def _timed(pat: str, text: str, timeout: float) -> float | None:
    q: mp.Queue = mp.Queue()
    p = mp.Process(target=_child, args=(pat, text, q))
    p.start()
    p.join(timeout)
    if p.is_alive():
        p.terminate()
        p.join()
        return None
    return q.get() if not q.empty() else 0.0


def linear_search_time(
    pattern: str, mk_input: Callable[[int], str], sizes: list[int], timeout: float = 2.0
) -> list[float | None]:
    return [_timed(pattern, mk_input(size), timeout) for size in sizes]


_ADVERSARIAL_INPUTS: list[Callable[[int], str]] = [
    lambda n: "/" * n,
    lambda n: " " * n,
    lambda n: "<" * n,
    lambda n: "." * n,
    lambda n: "a" * n,
    lambda n: ("/x<. a" * (n // 6 + 1))[:n],
    lambda n: "SELECT " + " " * n,
]


@pytest.mark.parametrize("pat,_ctx,cat", SusPatternsManager._pattern_definitions)
def test_builtin_pattern_is_not_catastrophic(
    pat: str, _ctx: frozenset[str], cat: str
) -> None:
    for mk in _ADVERSARIAL_INPUTS:
        elapsed = linear_search_time(pat, mk, [40000], timeout=2.0)[0]
        assert elapsed is not None, (
            f"{cat} pattern did not finish in 2s on 40k adversarial input: {pat!r}"
        )
        assert elapsed < 1.0, (
            f"{cat} pattern took {elapsed:.2f}s on 40k adversarial input "
            f"(super-linear): {pat!r}"
        )


def test_select_from_resists_repeated_anchor_padding() -> None:
    pat = next(
        p
        for p, _c, c in SusPatternsManager._pattern_definitions
        if c == "sqli" and "FROM" in p
    )
    sizes = [4000, 8000, 16000]
    times = linear_search_time(pat, lambda n: "SELECT " * (n // 7), sizes, timeout=2.0)
    assert all(t is not None for t in times), (
        f"repeated-SELECT-no-FROM input did not finish: {pat!r}"
    )
    first, last = times[0], times[-1]
    assert first is not None and last is not None
    ratio = last / first if first > 0 else 0.0
    assert ratio < 8.0, (
        f"repeated-SELECT-no-FROM input grew {ratio:.1f}x over a 4x size increase "
        f"(quadratic behavior): {pat!r} times={times}"
    )


def _compiled(cat: str, needle: str) -> re.Pattern:
    for pat, _c, c in SusPatternsManager._pattern_definitions:
        if c == cat and needle in pat:
            return re.compile(pat, IM)
    raise AssertionError(f"pattern not found: {cat}/{needle}")


def test_select_from_still_matches_real_sqli() -> None:
    rx = _compiled("sqli", "FROM")
    assert rx.search("SELECT username, password FROM users")
    assert rx.search("select * from accounts where 1=1")


def test_union_select_null_still_matches_real_sqli() -> None:
    rx = _compiled("sqli", r"NULL(?:[,\s]*NULL)*")
    assert rx.search("UNION SELECT NULL")
    assert rx.search("union all select null,null,null--")
    assert rx.search("(SELECT @@version)")
    assert rx.search("( select version())")


def test_union_select_null_resists_unterminated_separator_padding() -> None:
    rx = _compiled("sqli", r"NULL(?:[,\s]*NULL)*")
    sizes = [4000, 8000, 16000]
    times = linear_search_time(
        rx.pattern, lambda n: "UNION SELECT NULL" + ", " * n, sizes, timeout=2.0
    )
    assert all(t is not None for t in times), (
        f"unterminated-separator-padding input did not finish: {rx.pattern!r}"
    )
    first, last = times[0], times[-1]
    assert first is not None and last is not None
    ratio = last / first if first > 0 else 0.0
    assert ratio < 8.0, (
        f"unterminated-separator-padding input grew {ratio:.1f}x over a 4x size "
        f"increase (quadratic behavior): {rx.pattern!r} times={times}"
    )


def test_recon_ext_still_matches_real_probe() -> None:
    rx = _compiled("recon", r"(?:asp|aspx")
    assert rx.search("/admin/config.aspx")
    assert rx.search("/shell.jsp?x=1")


@pytest.mark.parametrize(
    "path",
    [
        "/report.final.jsp",
        "/backup.2024.jsp",
        "/app.v1.2.do",
        "/db.dump.cgi",
        "/web.config.bak.jsp",
    ],
)
def test_recon_ext_still_matches_multidot_filenames(path: str) -> None:
    rx = _compiled("recon", r"(?:asp|aspx")
    assert rx.search(path), f"multi-dot recon probe regressed: {path}"


def test_xss_href_javascript_still_matches_real_attack() -> None:
    rx = _compiled("xss", "href|src|data|action")
    assert rx.search('<a href="javascript:alert(1)">click</a>')
    assert rx.search('<img src="x" onerror="alert(1)" href="javascript:alert(2)">')


def test_xss_href_javascript_resists_padding_evasion() -> None:
    rx = _compiled("xss", "href|src|data|action")
    padded = "<a " + ('data-x="junk" ' * 30) + 'href="javascript:alert(1)">'
    assert len(padded) - len("<a ") > 256, "padding must exceed the old 256-char bound"
    assert rx.search(padded), "padded attack evaded detection"


def test_xss_style_expression_still_matches_real_attack() -> None:
    rx = _compiled("xss", "expression|behavior|url")
    assert rx.search('<div style="width:expression(alert(1))">')


def test_xss_style_expression_resists_padding_evasion() -> None:
    rx = _compiled("xss", "expression|behavior|url")
    padded = '<div style="' + ("color:red;" * 40) + 'width:expression(alert(1))">'
    assert len(padded) > 256, "padding must exceed the old 256-char bound"
    assert rx.search(padded), "padded attack evaded detection"


def test_recon_secrets_still_matches_bare_filename() -> None:
    rx = _compiled("recon", "secrets?|credentials?")
    assert rx.search("/secrets.json")
    assert rx.search("/app/config/credentials.yml")


@pytest.mark.parametrize(
    "path",
    [
        "/my.secrets.json",
        "/db.credentials.env",
        "/backup.old.secrets.json",
    ],
)
def test_recon_secrets_still_matches_multidot_filenames(path: str) -> None:
    rx = _compiled("recon", "secrets?|credentials?")
    assert rx.search(path), f"multi-dot secrets probe regressed: {path}"


@pytest.mark.parametrize(
    "path",
    [
        "/static/js/main.abc123.js.map",
    ],
)
def test_sensitive_file_map_still_matches_multidot_filenames(path: str) -> None:
    rx = _compiled("sensitive_file", r"\.map")
    assert rx.search(path), f"multi-dot source-map probe regressed: {path}"


@pytest.mark.parametrize(
    "path",
    [
        "/legacy.v2.old.py",
    ],
)
def test_sensitive_file_source_still_matches_multidot_filenames(path: str) -> None:
    rx = _compiled("sensitive_file", "ts|tsx|jsx")
    assert rx.search(path), f"multi-dot source-file probe regressed: {path}"


@pytest.mark.parametrize(
    "path",
    [
        "/site.v1.2.bak",
    ],
)
def test_cms_probing_backup_still_matches_multidot_filenames(path: str) -> None:
    rx = _compiled("cms_probing", "bak|backup|old")
    assert rx.search(path), f"multi-dot backup probe regressed: {path}"


def test_every_builtin_passes_the_safety_validator() -> None:
    pc = PatternCompiler()
    bad = []
    for pat, _c, cat in SusPatternsManager._pattern_definitions:
        ok, reason = pc.validate_pattern_safety(pat)
        if not ok:
            bad.append((cat, reason, pat))
    assert not bad, "built-ins that fail the ReDoS validator:\n" + "\n".join(
        f"  [{c}] {r} :: {p[:80]}" for c, r, p in bad
    )
