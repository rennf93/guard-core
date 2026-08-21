import json
import re
import statistics
import time
from collections.abc import Callable

from guard_core.detection_engine.scan_window import bounded_search

_SIZES = (262144, 524288)
_RAW_DEMO_SIZES = (8192, 16384)
_RUNS = 5

_SINGLE_GAP_COMPILED = re.compile(r"<script[^>]*>", re.IGNORECASE)
_TWO_GAP_COMPILED = re.compile(r"<script[^>]*>[^<]*<\/script\s*>", re.IGNORECASE)
_PREFIX = re.compile(r"<script", re.IGNORECASE)
_TERMINATOR = re.compile(r">")
_TWO_GAP_TERMINATOR = re.compile(r"<\/script\s*>", re.IGNORECASE)


def _no_terminator_fill(size: int) -> str:
    block = "<script "
    return block * (size // len(block))


def _one_prefix_many_terminators_fill(size: int) -> str:
    unit = "</script>" + ("x" * 50)
    return "<script" + unit * (size // len(unit))


def _many_prefixes_one_terminator_fill(size: int) -> str:
    unit = "<script " + ("x" * 100) + ">"
    return (unit * (size // len(unit))) + "alert(1)</script>"


_FILLS: dict[str, Callable[[int], str]] = {
    "no_terminator": _no_terminator_fill,
    "one_prefix_many_terminators": _one_prefix_many_terminators_fill,
    "many_prefixes_one_terminator": _many_prefixes_one_terminator_fill,
}


def _cpu_runs(fn: Callable[[str], object], text: str, runs: int) -> dict[str, float]:
    samples = []
    for _ in range(runs):
        start = time.process_time()
        fn(text)
        samples.append(time.process_time() - start)
    return {"min": min(samples), "median": statistics.median(samples)}


def _measure_bounded() -> dict[str, object]:
    def _bounded_single_gap(text: str) -> object:
        return bounded_search(text, _SINGLE_GAP_COMPILED, _PREFIX, _TERMINATOR)

    def _bounded_two_gap(text: str) -> object:
        return bounded_search(text, _TWO_GAP_COMPILED, _PREFIX, _TWO_GAP_TERMINATOR)

    results: dict[str, object] = {}
    for shape_name, fill in _FILLS.items():
        bounded_fn = (
            _bounded_single_gap if shape_name == "no_terminator" else _bounded_two_gap
        )
        bounded_runs = [_cpu_runs(bounded_fn, fill(size), _RUNS) for size in _SIZES]
        results[shape_name] = {"sizes": list(_SIZES), "bounded": bounded_runs}
    return results


def _measure_raw_quadratic_demo() -> dict[str, object]:
    def _raw(text: str) -> object:
        return _SINGLE_GAP_COMPILED.search(text)

    def _bounded(text: str) -> object:
        return bounded_search(text, _SINGLE_GAP_COMPILED, _PREFIX, _TERMINATOR)

    raw_runs = []
    bounded_runs = []
    for size in _RAW_DEMO_SIZES:
        text = _no_terminator_fill(size)
        raw_runs.append(_cpu_runs(_raw, text, _RUNS))
        bounded_runs.append(_cpu_runs(_bounded, text, _RUNS))
    return {"sizes": list(_RAW_DEMO_SIZES), "raw": raw_runs, "bounded": bounded_runs}


def _measure() -> dict[str, object]:
    return {
        "shapes": _measure_bounded(),
        "raw_quadratic_demo": _measure_raw_quadratic_demo(),
    }


if __name__ == "__main__":
    print(json.dumps(_measure()))
