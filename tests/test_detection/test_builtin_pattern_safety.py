import multiprocessing as mp
import re
import time
from collections.abc import Callable

import pytest

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


ADVERSARIAL = {
    "sqli": lambda n: "SELECT " + " " * n,
    "recon": lambda n: "/" * n,
    "xss": lambda n: "<" * n,
}


@pytest.mark.parametrize("pat,_ctx,cat", SusPatternsManager._pattern_definitions)
def test_builtin_pattern_is_not_catastrophic(
    pat: str, _ctx: frozenset[str], cat: str
) -> None:
    mk = ADVERSARIAL.get(cat, lambda n: "A" * n)
    elapsed = linear_search_time(pat, mk, [40000], timeout=2.0)[0]
    assert elapsed is not None, (
        f"{cat} pattern did not finish in 2s on 40k input: {pat!r}"
    )
    assert elapsed < 1.0, (
        f"{cat} pattern took {elapsed:.2f}s on 40k input (super-linear): {pat!r}"
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


def test_recon_ext_still_matches_real_probe() -> None:
    rx = _compiled("recon", r"(?:asp|aspx")
    assert rx.search("/admin/config.aspx")
    assert rx.search("/shell.jsp?x=1")


def test_xss_href_javascript_still_matches_real_attack() -> None:
    rx = _compiled("xss", "href|src|data|action")
    assert rx.search('<a href="javascript:alert(1)">click</a>')
    assert rx.search('<img src="x" onerror="alert(1)" href="javascript:alert(2)">')


def test_xss_style_expression_still_matches_real_attack() -> None:
    rx = _compiled("xss", "expression|behavior|url")
    assert rx.search('<div style="width:expression(alert(1))">')


def test_recon_secrets_still_matches_bare_filename() -> None:
    rx = _compiled("recon", "secrets?|credentials?")
    assert rx.search("/secrets.json")
    assert rx.search("/app/config/credentials.yml")
