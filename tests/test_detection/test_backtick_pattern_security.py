import random
import re

import pytest

from guard_core.handlers._suspatterns_pattern_table import _PATTERN_DEFINITIONS
from tests.test_detection.test_builtin_pattern_safety import _timed_batch

_ORIGINAL = (
    r"\A\s*(?:[;&|]\s*)*`\s*(?:[A-Za-z0-9_./~]|\$[({])"
    r"(?:[^`\\\n]|\\.)*\s*`"
    r"(?:\s*[;&|]\s*`\s*(?:[A-Za-z0-9_./~]|\$[({])(?:[^`\\\n]|\\.)*\s*`)*"
    r"\s*(?:[;&|]\s*)*\Z"
)
_CURRENT = next(
    pattern
    for pattern, _context, category in _PATTERN_DEFINITIONS
    if category == "cmd_injection" and pattern.startswith(r"\A\s*(?:[;&|]\s*)*`")
)


@pytest.mark.parametrize("flags", [0, re.I | re.M, re.I | re.ASCII])
def test_backtick_whitespace_rewrite_preserves_matches(flags: int) -> None:
    original = re.compile(_ORIGINAL, flags)
    current = re.compile(_CURRENT, flags)
    rng = random.Random(3409)
    whitespace = ["", " ", "\t", "\r", "\n", " \n\t\n", "\u2003", "\x85"]
    bodies = ["a", "$(id)", "${a}", "a b", "a\\`b", "a\\\\", "a\\\nb", "a\nb", "K"]
    commands = [
        f"`{lead}{body}{tail}`"
        for lead in whitespace
        for body in bodies
        for tail in whitespace
    ]
    values = list(commands)
    values.extend(
        rng.choice(whitespace)
        + rng.choice(["", ";", "&&", "| \n"])
        + rng.choice(commands)
        + rng.choice(["", ";", " | ", "&&"])
        + rng.choice(commands)
        + rng.choice(whitespace)
        + rng.choice(["", "X", ";", " | "])
        for _ in range(10000)
    )
    values.extend(
        "".join(rng.choices("`a $({;&|\\\n\t\u2003", k=40)) for _ in range(2000)
    )
    for value in values:
        expected = [
            (match.span(), match.groups()) for match in original.finditer(value)
        ]
        actual = [(match.span(), match.groups()) for match in current.finditer(value)]
        assert actual == expected, repr(value)


@pytest.mark.parametrize("prefix", ["`a", "`a`;`b"])
@pytest.mark.parametrize("padding", [" ", "\t", "\u2003", "\n"])
@pytest.mark.parametrize("ending", ["X", "`X"])
@pytest.mark.redos_timing
def test_backtick_missing_delimiter_and_bad_suffix_scale_linearly(
    prefix: str, padding: str, ending: str
) -> None:
    measurements = _timed_batch(
        _CURRENT,
        [prefix + padding * size + ending for size in (16384, 32768, 65536, 131072)],
        timeout=15.0,
    )
    assert measurements is not None
    assert len(measurements) == 4
    assert measurements[-1] / max(measurements[0], 0.001) < 24, measurements


@pytest.mark.parametrize("padding", [" ", "\n", "\n\u2003", "\r\t"])
def test_backtick_newline_and_long_padding_remain_detectable(padding: str) -> None:
    value = "`a" + padding * 4096 + "`;`b" + padding * 4096 + "`"
    assert re.fullmatch(_CURRENT, value, re.I | re.M) is not None
