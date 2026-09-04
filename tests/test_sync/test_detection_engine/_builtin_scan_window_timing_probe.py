import json
import os
import re
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path

_SIZES = (32768, 65536, 131072, 262144)
_REPS = 9

_REACH_PROBE_UNITS: dict[str, str] = {
    r"<script[^>]*>[^<]*<\/script\s*>": "<script",
    (
        r"(?:<[A-Za-z/][^<>]*style\s*=\s{0,20}[\"']?[^<>\"']*"
        r"(?:expression|behavior|url)\s*\([^)]*\))"
    ): "<a style=",
    r"(?:<object[^>]*>[\s\S]*<\/object\s*>)": "<object",
    r"(?:<embed[^>]*>[\s\S]*<\/embed\s*>)": "<embed",
    r"(?:<applet[^>]*>[\s\S]*<\/applet\s*>)": "<applet",
    r"\.\.;[^/\\]*[/\\]": "..;",
    (
        r"=(?:https?|ftp):\/\/[^\s'\"<>]+\/[^\s'\"<>\/]*"
        r"\.(?:phtml|php[3-5]?|phar|jsp|aspx?|pl|py|txt|inc)(?![a-zA-Z0-9])"
    ): "=http://",
    r"<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>": "<!ENTITY",
    r"(?:<!\[CDATA\[.*?\]\]>)": "<![CDATA[",
    r"<!DOCTYPE[^>\[]*\[[\s\S]*?<!ENTITY": "<!DOCTYPE",
}


_BoundPairs = tuple[tuple[re.Pattern[str], re.Pattern[str]], ...]
_BoundedMatchesFn = Callable[
    [str, re.Pattern[str], _BoundPairs], Iterator[re.Match[str]]
]


def _cpu_min(fn: Callable[..., object], args: tuple[object, ...], reps: int) -> float:
    best = float("inf")
    for _ in range(reps):
        start = time.process_time()
        fn(*args)
        elapsed = time.process_time() - start
        best = min(best, elapsed)
    return best


def _measure_one(
    source: str,
    unit: str,
    sizes: tuple[int, ...],
    bounds: _BoundPairs,
    bounded_matches: _BoundedMatchesFn,
) -> list[float]:
    compiled = re.compile(source, re.IGNORECASE)

    def _first_match(text: str) -> re.Match[str] | None:
        return next(bounded_matches(text, compiled, bounds), None)

    bounded_times: list[float] = []
    for size in sizes:
        reps = size // len(unit) + 1
        text = (unit * reps)[:size]
        bounded_times.append(_cpu_min(_first_match, (text,), _REPS))

    return bounded_times


def _measure_all() -> dict[str, list[float]]:
    from guard_core.sync.handlers.suspatterns_handler import (
        _SCAN_WINDOW_PATTERNS,
        _SSTI_HASH_BRACE_SHAPE_RE,
    )
    from guard_core.sync.handlers.suspatterns_handler import (
        _iter_scan_window_matches as bounded_matches,
    )

    units = dict(_REACH_PROBE_UNITS)
    units[_SSTI_HASH_BRACE_SHAPE_RE] = "#{"

    return {
        source: _measure_one(
            source, unit, _SIZES, _SCAN_WINDOW_PATTERNS[source], bounded_matches
        )
        for source, unit in units.items()
    }


def _find_project_root(start: Path) -> Path:
    for candidate in (start, *start.parents):
        if (candidate / "pyproject.toml").is_file():
            return candidate
    raise RuntimeError(f"no pyproject.toml found above {start}")


def main() -> None:
    tree = str(_find_project_root(Path(__file__).resolve()))
    sys.path.insert(0, tree)
    import guard_core

    guard_core_tree = os.path.dirname(os.path.dirname(guard_core.__file__))
    assert guard_core_tree == tree, guard_core.__file__

    print(json.dumps(_measure_all()))


if __name__ == "__main__":
    main()
