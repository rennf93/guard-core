import re
import string

from guard_core.sync.detection_engine._redos_ambiguous_tail import (
    _representative_char_for_atom,
)
from guard_core.sync.detection_engine._redos_structure import (
    _MAX_GROUP_NESTING_DEPTH,
    _find_group_end,
    _skip_char_class,
    _split_top_level_alternations,
)

_PROBE_REACH_STRESS_LEN = 4000
_PROBE_REACH_BOUNDED_CAP = 4000
_PROBE_REACH_TOTAL_BUDGET = 12000
_PROBE_REACH_GROUP_REPEAT_CAP = 3
_PROBE_REACH_BREAK_CHAR_CANDIDATES = "\x01\x02\x03\x04\x05\x06\x07\x08"
_PROBE_REACH_ZERO_WIDTH_ESCAPES = frozenset("AZbB")
_PROBE_REACH_LOOKAROUND_PREFIXES = ("?=", "?!", "?<=", "?<!")


def _reach_budget_clamped_count(
    budget: list[int], unit_len: int, low: int, high: int
) -> int:
    if unit_len <= 0:
        return high
    affordable = max(0, budget[0]) // unit_len
    return max(low, min(high, affordable))


def _reach_symbol_quantifier_range(text: str, k: int, c: str) -> tuple[int, int, int]:
    end = k + 1
    if end < len(text) and text[end] == "?":
        end += 1
    if c == "*":
        return 0, _PROBE_REACH_STRESS_LEN, end
    if c == "+":
        return 1, _PROBE_REACH_STRESS_LEN, end
    return 0, 1, end


def _reach_brace_quantifier_high(parts: list[str]) -> int | None:
    if len(parts) == 1:
        return int(parts[0])
    if parts[1] == "":
        return _PROBE_REACH_STRESS_LEN
    if parts[1].isdigit():
        return int(parts[1])
    return None


def _reach_brace_quantifier_range(text: str, k: int) -> tuple[int, int, int] | None:
    end_brace = text.find("}", k)
    if end_brace == -1:
        return None
    parts = text[k + 1 : end_brace].split(",")
    if not parts[0].isdigit():
        return None
    low = int(parts[0])
    high = _reach_brace_quantifier_high(parts)
    if high is None:
        return None
    end = end_brace + 1
    if end < len(text) and text[end] == "?":
        end += 1
    return low, max(low, min(high, _PROBE_REACH_BOUNDED_CAP)), end


def _reach_quantifier_repeat_range(text: str, k: int) -> tuple[int, int, int]:
    if k >= len(text):
        return 1, 1, k
    c = text[k]
    if c in "*+?":
        return _reach_symbol_quantifier_range(text, k, c)
    if c != "{":
        return 1, 1, k
    brace_range = _reach_brace_quantifier_range(text, k)
    return brace_range if brace_range is not None else (1, 1, k)


_PROBE_REACH_INLINE_FLAG_SCOPED_RE = re.compile(r"\A\?[aiLmsux]*(?:-[aiLmsux]+)?:")
_PROBE_REACH_INLINE_FLAG_ONLY_RE = re.compile(r"\A\?[aiLmsux]*(?:-[aiLmsux]+)?\Z")
_PROBE_REACH_COMMENT_GROUP_RE = re.compile(r"\A\?#")


def _reach_group_walk_target(raw_inner: str) -> tuple[str | None, bool]:
    if not raw_inner.startswith("?"):
        return raw_inner, False
    if raw_inner.startswith("?:"):
        return raw_inner[2:], False
    if raw_inner.startswith("?P<"):
        close = raw_inner.find(">")
        return (raw_inner[close + 1 :] if close != -1 else None), False
    if raw_inner.startswith(_PROBE_REACH_LOOKAROUND_PREFIXES):
        return None, True
    if _PROBE_REACH_COMMENT_GROUP_RE.match(raw_inner):
        return None, True
    flag_scoped = _PROBE_REACH_INLINE_FLAG_SCOPED_RE.match(raw_inner)
    if flag_scoped:
        return raw_inner[flag_scoped.end() :], False
    if _PROBE_REACH_INLINE_FLAG_ONLY_RE.match(raw_inner):
        return None, True
    return None, False


def _reach_stress_fill(
    text: str, token_end: int, rep: str, chars_seen: set[str], budget: list[int]
) -> tuple[str, int]:
    low, high, next_i = _reach_quantifier_repeat_range(text, token_end)
    count = _reach_budget_clamped_count(budget, len(rep), low, high)
    budget[0] -= len(rep) * count
    chars_seen.add(rep)
    return rep * count, next_i


def _reach_hex_escape_span(text: str, i: int) -> bool:
    n = len(text)
    return (
        text[i + 1] == "x"
        and i + 3 < n
        and text[i + 2] in string.hexdigits
        and text[i + 3] in string.hexdigits
    )


def _synth_escape_atom(
    text: str,
    i: int,
    chars_seen: set[str],
    budget: list[int],
    group_texts: dict[int, str],
) -> tuple[str, int] | None:
    if i + 1 >= len(text):
        return None
    letter = text[i + 1]
    is_hex_escape = _reach_hex_escape_span(text, i)
    token_end = i + 4 if is_hex_escape else i + 2
    if letter in _PROBE_REACH_ZERO_WIDTH_ESCAPES:
        return "", token_end
    if letter.isdigit():
        backref = group_texts.get(int(letter))
        if backref is None:
            return None
        return _reach_stress_fill(text, token_end, backref, chars_seen, budget)
    rep = (
        chr(int(text[i + 2 : i + 4], 16))
        if is_hex_escape
        else _representative_char_for_atom(text[i:token_end])
    )
    if rep is None:
        return None
    return _reach_stress_fill(text, token_end, rep, chars_seen, budget)


def _synth_char_class_atom(
    text: str, i: int, chars_seen: set[str], budget: list[int]
) -> tuple[str, int] | None:
    end = _skip_char_class(text, i)
    rep = _representative_char_for_atom(text[i:end])
    if rep is None:
        return None
    return _reach_stress_fill(text, end, rep, chars_seen, budget)


def _synth_dot_atom(
    text: str, i: int, chars_seen: set[str], budget: list[int]
) -> tuple[str, int]:
    return _reach_stress_fill(text, i + 1, "a", chars_seen, budget)


def _synth_group_atom(
    text: str,
    i: int,
    chars_seen: set[str],
    budget: list[int],
    depth: int,
    group_texts: dict[int, str],
    group_counter: list[int],
) -> tuple[str, int] | None:
    group_end = _find_group_end(text, i)
    if group_end is None:
        return None
    raw_inner = text[i + 1 : group_end - 1]
    reserved_number = None
    if not raw_inner.startswith("?") or raw_inner.startswith("?P<"):
        group_counter[0] += 1
        reserved_number = group_counter[0]
    walk_inner, skip = _reach_group_walk_target(raw_inner)
    if skip:
        return "", group_end
    if walk_inner is None:
        return None
    first_branch = _split_top_level_alternations(walk_inner)[0]
    sub_text, sub_ok = _synthesize_reaching_probe_segment(
        first_branch, chars_seen, budget, depth + 1, group_texts, group_counter
    )
    if not sub_ok:
        return None
    if reserved_number is not None:
        group_texts[reserved_number] = sub_text
    low, high, next_i = _reach_quantifier_repeat_range(text, group_end)
    high = max(low, min(high, _PROBE_REACH_GROUP_REPEAT_CAP))
    count = _reach_budget_clamped_count(budget, len(sub_text), low, high)
    budget[0] -= len(sub_text) * count
    return sub_text * count, next_i


def _synth_next_atom(
    text: str,
    i: int,
    chars_seen: set[str],
    budget: list[int],
    depth: int,
    group_texts: dict[int, str],
    group_counter: list[int],
) -> tuple[str, int] | None:
    c = text[i]
    if c == "\\":
        return _synth_escape_atom(text, i, chars_seen, budget, group_texts)
    if c == "[":
        return _synth_char_class_atom(text, i, chars_seen, budget)
    if c == ".":
        return _synth_dot_atom(text, i, chars_seen, budget)
    if c == "(":
        return _synth_group_atom(
            text, i, chars_seen, budget, depth, group_texts, group_counter
        )
    return _reach_stress_fill(text, i + 1, c, chars_seen, budget)


def _synthesize_reaching_probe_segment(
    text: str,
    chars_seen: set[str],
    budget: list[int],
    depth: int,
    group_texts: dict[int, str],
    group_counter: list[int],
) -> tuple[str, bool]:
    if depth > _MAX_GROUP_NESTING_DEPTH:
        return "", False
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        if text[i] in "^$":
            i += 1
            continue
        result = _synth_next_atom(
            text, i, chars_seen, budget, depth, group_texts, group_counter
        )
        if result is None:
            return "", False
        piece, i = result
        out.append(piece)
    return "".join(out), True


def _synthesize_reaching_probe(pattern: str) -> str | None:
    chars_seen: set[str] = set()
    budget = [_PROBE_REACH_TOTAL_BUDGET]
    group_texts: dict[int, str] = {}
    group_counter = [0]
    body, ok = _synthesize_reaching_probe_segment(
        pattern, chars_seen, budget, 0, group_texts, group_counter
    )
    if not ok:
        return None
    breaking = next(
        (ch for ch in _PROBE_REACH_BREAK_CHAR_CANDIDATES if ch not in chars_seen),
        None,
    )
    if breaking is None:
        return None
    return body + breaking
