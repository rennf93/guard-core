import re
from collections.abc import Iterator


def _skip_char_class(text: str, i: int) -> int:
    j = i + 1
    while j < len(text) and text[j] != "]":
        if text[j] == "\\" and j + 1 < len(text):
            j += 2
            continue
        j += 1
    if j < len(text):
        j += 1
    return j


def _strip_escapes_and_char_classes(pattern: str) -> str:
    result: list[str] = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            result.append("X")
            i += 2
            continue
        if c == "[":
            i = _skip_char_class(pattern, i)
            result.append("X")
            continue
        result.append(c)
        i += 1
    return "".join(result)


def _branch_is_unbounded_single(branch: str) -> bool:
    if re.fullmatch(r".[*+]", branch):
        return True
    if re.fullmatch(r".\{[0-9]+,\}", branch):
        return True
    return False


def _advance_past_escape_or_char_class(text: str, i: int) -> int | None:
    if text[i] == "\\" and i + 1 < len(text):
        return i + 2
    if text[i] == "[":
        return _skip_char_class(text, i)
    return None


def _find_group_end(text: str, start: int) -> int | None:
    depth = 1
    j = start + 1
    while j < len(text) and depth > 0:
        skip_to = _advance_past_escape_or_char_class(text, j)
        if skip_to is not None:
            j = skip_to
            continue
        c = text[j]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        j += 1
    if depth != 0:
        return None
    return j


def _normalize_group_inner(inner: str) -> str | None:
    if inner.startswith("?:"):
        return inner[2:]
    if inner.startswith("?P="):
        return None
    if inner.startswith("?P<"):
        end_name = inner.find(">")
        if end_name == -1:
            return None
        return inner[end_name + 1 :]
    return inner


def _unwrap_transparent_wrapper(text: str) -> str:
    while text.startswith("("):
        end = _find_group_end(text, 0)
        if end is None or end != len(text):
            break
        candidate = _normalize_group_inner(text[1 : end - 1])
        if candidate is None:
            break
        text = candidate
    return text


def _outer_quantifier_len(text: str, k: int) -> int:
    if k < len(text) and text[k] in "*+":
        return 1
    if k < len(text) and text[k] == "{":
        end_brace = text.find("}", k)
        if end_brace != -1:
            brace_inner = text[k + 1 : end_brace]
            if "," in brace_inner and brace_inner.split(",")[1] == "":
                return end_brace - k + 1
    return 0


def _branches_overlap(branches: list[str]) -> bool:
    n = len(branches)
    for a in range(n):
        for b in range(a + 1, n):
            x = branches[a]
            y = branches[b]
            if x == y or x.startswith(y) or y.startswith(x):
                return True
    return False


_META_BRANCH_CHARS = set("()[]{}.*+?^$|\\")


def _is_pure_literal_branch(branch: str) -> bool:
    return bool(branch) and all(c not in _META_BRANCH_CHARS for c in branch)


def _split_top_level_alternations(inner: str) -> list[str]:
    branches: list[str] = []
    depth = 0
    start = 0
    k = 0
    while k < len(inner):
        skip_to = _advance_past_escape_or_char_class(inner, k)
        if skip_to is not None:
            k = skip_to
            continue
        c = inner[k]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "|" and depth == 0:
            branches.append(inner[start:k])
            start = k + 1
        k += 1
    branches.append(inner[start:])
    return branches


def _overlapping_literal_branches(inner: str) -> bool:
    literal_branches = [
        b for b in _split_top_level_alternations(inner) if _is_pure_literal_branch(b)
    ]
    return len(literal_branches) >= 2 and _branches_overlap(literal_branches)


_MAX_GROUP_NESTING_DEPTH = 20


class GroupNestingTooDeep(Exception):
    pass


def _iter_quantified_group_bodies_at(
    pattern: str, base: int, depth: int
) -> Iterator[tuple[int, int, str]]:
    if depth > _MAX_GROUP_NESTING_DEPTH:
        raise GroupNestingTooDeep(_MAX_GROUP_NESTING_DEPTH)
    i = 0
    while i < len(pattern):
        if pattern[i] != "(":
            i += 1
            continue
        j = _find_group_end(pattern, i)
        if j is None:
            i += 1
            continue
        raw_inner = pattern[i + 1 : j - 1]
        yield from _iter_quantified_group_bodies_at(raw_inner, base + i + 1, depth + 1)
        inner = _normalize_group_inner(raw_inner)
        if inner is not None:
            inner = _unwrap_transparent_wrapper(inner)
            qlen = _outer_quantifier_len(pattern, j)
            if qlen > 0:
                yield base + i, base + j + qlen, inner
        i = j


def _iter_quantified_group_bodies(pattern: str) -> Iterator[tuple[int, int, str]]:
    yield from _iter_quantified_group_bodies_at(pattern, 0, 0)
