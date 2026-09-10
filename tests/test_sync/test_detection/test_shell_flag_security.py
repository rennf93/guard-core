import random
import re

import pytest

from guard_core.sync.detection_engine.compiler import PatternCompiler
from guard_core.sync.handlers._suspatterns_sources import (
    _CMD_INJECTION_SHELL_DASH_FLAG_RE,
)

_PREVIOUS_SOURCE = (
    r"(?:\A|[;|&])\s*(?:/?(?:[\w.-]+/)*env\s+)?/?(?:[\w.-]+/)*"
    r"(?:bash|sh|ksh|csh|tsch|zsh|ash)\s+-[a-zA-Z]+"
    r"(?:\s+(?:'[^']*'|\"[^\"]*\"|[^\s;|&]+))?"
    r"(?=\s*(?:[;|&]|\Z))"
)


@pytest.mark.parametrize("flags", [0, re.I | re.M, re.I | re.ASCII])
def test_shell_flag_shared_path_prefix_preserves_matches(flags: int) -> None:
    previous = re.compile(_PREVIOUS_SOURCE, flags)
    current = re.compile(_CMD_INJECTION_SHELL_DASH_FLAG_RE, flags)
    rng = random.Random(9371)
    tokens = [
        "env",
        "sh",
        "bash",
        "/",
        "usr/",
        "ENV",
        "\n",
        " ",
        "\t",
        "&",
        ";",
        "|",
        "-c",
        "-e",
        "'id'",
        '"x"',
        "x",
        "K/",
        "env/",
        "-",
        "\u2003",
    ]
    cases = [
        f"{start}{env}{path}{shell} {flag}{arg}{end}"
        for start in ["", "; ", "&\n", "x|", "bad "]
        for env in ["", "env ", "/usr/bin/env\t", "env/env ", "ENV "]
        for path in ["", "/", "usr/", "/env/", "env/env/"]
        for shell in ["sh", "bash", "ksh", "SH", "x"]
        for flag in ["-c", "-ec", "-", "-1"]
        for arg in ["", " 'id'", ' "hello world"', " x", " 'broken"]
        for end in ["", ";", " &", "\nx"]
    ]
    cases.extend("".join(rng.choices(tokens, k=20)) for _ in range(10000))
    for text in cases:
        expected = [(m.span(), m.group()) for m in previous.finditer(text)]
        actual = [(m.span(), m.group()) for m in current.finditer(text)]
        assert actual == expected, (text, actual, expected)


@pytest.mark.redos_timing
def test_shell_flag_shared_path_prefix_passes_cost_validation() -> None:
    safe, reason = PatternCompiler().validate_pattern_safety(
        _CMD_INJECTION_SHELL_DASH_FLAG_RE
    )
    assert safe, reason
