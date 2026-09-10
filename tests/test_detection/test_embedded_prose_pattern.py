import itertools
import re

import pytest

from guard_core.handlers._suspatterns_sources import (
    _ATTACK_REPORT_LEXICON_RE,
    _PATH_ONLY_CHAR_RE,
    _PATH_ONLY_SEP_RE,
    _SINGLE_LINE_PREFIX_RE,
    _embedded_prose_pattern,
)

_REQUIRED = (
    r"etc/(?:passwd|shadow|group|hosts|motd|issue|mysql/my\.cnf|ssh/ssh_config)",
    r"\.env(?:\.\w+)?",
    r"\.(?:git|svn|hg|bzr)",
    r"(?:wp-(?:admin|login|content|includes|config)|administrator|xmlrpc)\.?"
    r"(?:php)?",
    r"(?:phpinfo|info|test|php_info)\.php",
    r"(?:\.htaccess|\.htpasswd|\.DS_Store|Thumbs\.db|\.npmrc|\.dockerenv|web\.config)",
)


def _prose_examples() -> list[str]:
    prefixes = ("scan ", "SCANNER ", "ordinary ", "scan\n", "scanning\u2028")
    paths = (
        ".env",
        ".env.local",
        ".git",
        "wp-admin",
        "wp-login.php",
        "xmlrpc.php",
        "phpinfo.php",
        ".htaccess",
        "web.config",
        "info.txt",
        "etc/hosts",
        "etc/mysql/my.cnf",
    )
    suffixes = ("", " attack", "\nattack", "!", "é", "\nscan")
    segments = (
        "",
        "/a",
        "/a/b",
        "/a/b/c",
        "/a/b/c/d",
        "/",
        "//a",
        "\\x\\y",
        "/" + "é" * 64,
        "/" + "é" * 65,
        "/a-/b%/c~",
        "/a./b",
    )
    return [
        prefix + separator + path + segment + suffix
        for prefix, separator, path, segment, suffix in itertools.product(
            prefixes, ("/", "\\"), paths, segments, suffixes
        )
    ]


@pytest.mark.parametrize("required", _REQUIRED)
@pytest.mark.parametrize("trailing_max", (0, 1, 3))
def test_embedded_prose_preserves_matches_and_spans(
    required: str, trailing_max: int
) -> None:
    old_tail = (
        rf"(?:{_PATH_ONLY_SEP_RE}{_PATH_ONLY_CHAR_RE}{{1,64}}){{0,{trailing_max}}}"
    )
    original = re.compile(
        rf"\A(?=(?:(?!\n).)*{_ATTACK_REPORT_LEXICON_RE})"
        rf"{_SINGLE_LINE_PREFIX_RE}{_PATH_ONLY_SEP_RE}"
        rf"(?:{required}){old_tail}\b",
        re.IGNORECASE | re.MULTILINE,
    )
    current = re.compile(
        _embedded_prose_pattern(required, trailing_max), re.IGNORECASE | re.MULTILINE
    )
    for text in _prose_examples():
        before, after = original.search(text), current.search(text)
        assert (before.span() if before else None) == (
            after.span() if after else None
        ), text
