from guard_core.detection_engine._redos_ambiguous_tail import _atom_char_set
from guard_core.detection_engine._redos_structure import (
    _find_group_end,
    _skip_char_class,
)


def _skip_lazy_marker(text: str, k: int) -> int:
    return k + 1 if k < len(text) and text[k] == "?" else k


def _brace_quantifier_span_allows_zero(text: str, k: int) -> tuple[int, bool]:
    end_brace = text.find("}", k)
    if end_brace == -1:
        return k, False
    parts = text[k + 1 : end_brace].split(",")
    low = parts[0]
    if low != "" and not low.isdigit():
        return k, False
    end = _skip_lazy_marker(text, end_brace + 1)
    return end, low in ("", "0")


def _quantifier_span_allows_zero(text: str, k: int) -> tuple[int, bool]:
    if k >= len(text):
        return k, False
    c = text[k]
    if c in "*?":
        return _skip_lazy_marker(text, k + 1), True
    if c == "+":
        return _skip_lazy_marker(text, k + 1), False
    if c == "{":
        return _brace_quantifier_span_allows_zero(text, k)
    return k, False


_ADVERSARIAL_RUN_HARD_RESET_CHARS = frozenset("|^$.")
_ADVERSARIAL_RUN_NARROW_CLASS_MAX_CHARS = 10


def _flush_adversarial_run(runs: list[str], current: list[str]) -> None:
    if current:
        runs.append("".join(current))
        current.clear()


def _adversarial_run_char_class_step(
    pattern: str, i: int, runs: list[str], current: list[str]
) -> int:
    end = _skip_char_class(pattern, i)
    chars = _atom_char_set(pattern[i:end])
    if 0 < len(chars) <= _ADVERSARIAL_RUN_NARROW_CLASS_MAX_CHARS:
        current.append(sorted(chars)[0])
    else:
        _flush_adversarial_run(runs, current)
    return end


def _adversarial_run_group_open_step(
    pattern: str,
    i: int,
    n: int,
    runs: list[str],
    current: list[str],
    stack: list[bool],
) -> int:
    if pattern[i + 1 : i + 3] == "?:":
        stack.append(True)
        return i + 3
    if i + 1 < n and pattern[i + 1] == "?":
        _flush_adversarial_run(runs, current)
        end_paren = _find_group_end(pattern, i)
        return end_paren if end_paren is not None else i + 1
    stack.append(False)
    _flush_adversarial_run(runs, current)
    return i + 1


def _adversarial_run_group_close_step(
    i: int, runs: list[str], current: list[str], stack: list[bool]
) -> int:
    transparent = stack.pop() if stack else False
    if not transparent:
        _flush_adversarial_run(runs, current)
    return i + 1


def _adversarial_run_escape_step(
    pattern: str, i: int, runs: list[str], current: list[str]
) -> int:
    nxt = pattern[i + 1]
    token_end = i + 2
    if nxt.isalnum():
        qend, allows_zero = _quantifier_span_allows_zero(pattern, token_end)
        if allows_zero:
            return qend
        _flush_adversarial_run(runs, current)
        return qend if qend > token_end else token_end
    current.append(nxt)
    return token_end


def _adversarial_run_step(
    pattern: str,
    i: int,
    n: int,
    runs: list[str],
    current: list[str],
    stack: list[bool],
) -> int:
    c = pattern[i]
    if c == "[":
        return _adversarial_run_char_class_step(pattern, i, runs, current)
    if c == "(":
        return _adversarial_run_group_open_step(pattern, i, n, runs, current, stack)
    if c == ")":
        return _adversarial_run_group_close_step(i, runs, current, stack)
    if c in _ADVERSARIAL_RUN_HARD_RESET_CHARS:
        _flush_adversarial_run(runs, current)
        return i + 1
    if c in "*+?":
        return i + 1
    if c == "{":
        end_brace = pattern.find("}", i)
        return end_brace + 1 if end_brace != -1 else i + 1
    if c == "\\" and i + 1 < n:
        return _adversarial_run_escape_step(pattern, i, runs, current)
    current.append(c)
    return i + 1


def _adversarial_literal_runs(pattern: str) -> list[str]:
    runs: list[str] = []
    current: list[str] = []
    stack: list[bool] = []
    i = 0
    n = len(pattern)
    while i < n:
        i = _adversarial_run_step(pattern, i, n, runs, current, stack)
    _flush_adversarial_run(runs, current)
    return [run for run in runs if run]
