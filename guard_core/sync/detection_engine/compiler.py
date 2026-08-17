import concurrent.futures
import logging
import re
import threading
import time
from collections.abc import Callable

logger = logging.getLogger("guard_core.sync.detection_engine.compiler")

_SHARED_EXECUTOR_MAX_WORKERS = 4

_shared_executor: concurrent.futures.ThreadPoolExecutor | None = None
_executor_lock = threading.Lock()

_consecutive_timeouts = 0
_timeout_lock = threading.Lock()

_validation_executor: concurrent.futures.ThreadPoolExecutor | None = None
_validation_executor_lock = threading.Lock()


def shared_regex_executor() -> concurrent.futures.ThreadPoolExecutor:
    global _shared_executor
    if _shared_executor is None:
        with _executor_lock:
            if _shared_executor is None:
                _shared_executor = concurrent.futures.ThreadPoolExecutor(
                    max_workers=_SHARED_EXECUTOR_MAX_WORKERS,
                    thread_name_prefix="guard-regex",
                )
    return _shared_executor


def validation_regex_executor() -> concurrent.futures.ThreadPoolExecutor:
    global _validation_executor
    if _validation_executor is None:
        with _validation_executor_lock:
            if _validation_executor is None:
                _validation_executor = concurrent.futures.ThreadPoolExecutor(
                    max_workers=1, thread_name_prefix="guard-regex-validate"
                )
    return _validation_executor


def report_scan_success() -> None:
    global _consecutive_timeouts
    if _consecutive_timeouts:
        with _timeout_lock:
            _consecutive_timeouts = 0


def report_scan_timeout() -> None:
    global _shared_executor, _consecutive_timeouts
    with _timeout_lock:
        _consecutive_timeouts += 1
        if _consecutive_timeouts < _SHARED_EXECUTOR_MAX_WORKERS:
            return
        stale_count = _consecutive_timeouts
        _consecutive_timeouts = 0
        with _executor_lock:
            stale_executor = _shared_executor
            _shared_executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=_SHARED_EXECUTOR_MAX_WORKERS,
                thread_name_prefix="guard-regex",
            )
    if stale_executor is not None:
        stale_executor.shutdown(wait=False)
    logger.warning(
        "guard_core shared regex scan pool replaced after %d consecutive "
        "timeouts; a slow pattern may have permanently occupied all workers",
        stale_count,
    )


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


def _find_group_end(text: str, start: int) -> int | None:
    depth = 1
    j = start + 1
    while j < len(text) and depth > 0:
        c = text[j]
        if c == "\\" and j + 1 < len(text):
            j += 2
            continue
        if c == "[":
            j = _skip_char_class(text, j)
            continue
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
    if inner.startswith("?P<") or inner.startswith("?P="):
        return None
    return inner


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
        c = inner[k]
        if c == "\\" and k + 1 < len(inner):
            k += 2
            continue
        if c == "[":
            k = _skip_char_class(inner, k)
            continue
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


def _detect_nested_unbounded_quantifier(pattern: str) -> str | None:
    i = 0
    while i < len(pattern):
        if pattern[i] != "(":
            i += 1
            continue
        j = _find_group_end(pattern, i)
        if j is None:
            i += 1
            continue
        inner = _normalize_group_inner(pattern[i + 1 : j - 1])
        if inner is None:
            i = j
            continue
        qlen = _outer_quantifier_len(pattern, j)
        if qlen > 0:
            stripped_inner = _strip_escapes_and_char_classes(inner)
            if any(_branch_is_unbounded_single(b) for b in stripped_inner.split("|")):
                return pattern[i : j + qlen]
            if _overlapping_literal_branches(inner):
                return pattern[i : j + qlen]
        i = j
    return None


def _extract_literal_chars(pattern: str) -> list[str]:
    chars: list[str] = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            i = _skip_char_class(pattern, i)
            continue
        if c.isalnum() or c in "_-./:@~ ":
            chars.append(c)
        i += 1
    return chars


def _pattern_derived_test_strings(pattern: str) -> list[str]:
    strings: list[str] = []
    seen: set[str] = set()
    for ch in _extract_literal_chars(pattern):
        if ch in seen or ch.isspace():
            continue
        seen.add(ch)
        if len(seen) > 8:
            break
        for length in (10, 100, 2000):
            strings.append(ch * length)
    return strings


class PatternCompiler:
    MAX_CACHE_SIZE = 1000

    def __init__(self, default_timeout: float = 5.0, max_cache_size: int = 1000):
        self.default_timeout = default_timeout
        self.max_cache_size = min(max_cache_size, 5000)
        self._compiled_cache: dict[str, re.Pattern] = {}
        self._cache_order: list[str] = []
        self._lock = threading.Lock()

    def compile_pattern(
        self, pattern: str, flags: int = re.IGNORECASE | re.MULTILINE
    ) -> re.Pattern:
        cache_key = f"{pattern}:{flags}"

        if cache_key in self._compiled_cache:
            with self._lock:
                if cache_key in self._compiled_cache:
                    self._cache_order.remove(cache_key)
                    self._cache_order.append(cache_key)
                    return self._compiled_cache[cache_key]

        with self._lock:
            if cache_key not in self._compiled_cache:
                if len(self._compiled_cache) >= self.max_cache_size:
                    oldest_key = self._cache_order.pop(0)
                    del self._compiled_cache[oldest_key]

                self._compiled_cache[cache_key] = re.compile(pattern, flags)
                self._cache_order.append(cache_key)

            return self._compiled_cache[cache_key]

    def compile_pattern_sync(
        self, pattern: str, flags: int = re.IGNORECASE | re.MULTILINE
    ) -> re.Pattern:
        return re.compile(pattern, flags)

    def validate_pattern_safety(
        self, pattern: str, test_strings: list[str] | None = None
    ) -> tuple[bool, str]:
        dangerous_patterns = [
            r"\(\.\*\)\+",
            r"\(\.\+\)\+",
            r"\([^)]*\*\)\+",
            r"\([^)]*\+\)\+",
            r"(?:\.\*){2,}",
            r"(?:\.\+){2,}",
        ]

        for dangerous in dangerous_patterns:
            if re.search(dangerous, pattern):
                return False, f"Pattern contains dangerous construct: {dangerous}"

        nested = _detect_nested_unbounded_quantifier(pattern)
        if nested is not None:
            return False, f"Pattern contains nested unbounded quantifier: {nested}"

        if test_strings is None:
            test_strings = [
                "a" * 10,
                "a" * 100,
                "a" * 2000,
                " " * 2000,
                "/" * 2000,
                "<" * 2000,
                "(" * 2000,
                "SELECT " + " " * 2000,
                "x" * 50 + "y" * 50,
                "<div " + "a" * 2000 + ">",
            ]
            test_strings.extend(_pattern_derived_test_strings(pattern))

        try:
            compiled = self.compile_pattern_sync(pattern)

            for test_str in test_strings:

                def _timed_search(text: str = test_str) -> float:
                    probe_start = time.monotonic()
                    compiled.search(text)
                    return time.monotonic() - probe_start

                future = validation_regex_executor().submit(_timed_search)
                try:
                    elapsed = future.result(timeout=1.0)
                except concurrent.futures.TimeoutError:
                    return (
                        False,
                        f"Pattern timed out on test string of length {len(test_str)}",
                    )

                if elapsed > 0.05:
                    return (
                        False,
                        f"Pattern timed out on test string of length {len(test_str)}",
                    )
        except Exception as e:
            return False, f"Pattern validation failed: {str(e)}"

        return True, "Pattern appears safe"

    def create_safe_matcher(
        self,
        pattern: str | re.Pattern,
        timeout: float | None = None,
        inline_safe: bool = False,
    ) -> Callable[[str], re.Match | None]:
        compiled = (
            pattern
            if isinstance(pattern, re.Pattern)
            else self.compile_pattern_sync(pattern)
        )
        match_timeout = timeout or self.default_timeout

        if inline_safe:

            def inline_safe_match(text: str) -> re.Match | None:
                return compiled.search(text)

            return inline_safe_match

        def safe_match(text: str) -> re.Match | None:
            future = shared_regex_executor().submit(compiled.search, text)
            try:
                result = future.result(timeout=match_timeout)
                report_scan_success()
                return result
            except concurrent.futures.TimeoutError:
                future.cancel()
                report_scan_timeout()
                return None
            except Exception:
                return None

        return safe_match

    def create_safe_finditer_matcher(
        self,
        pattern: str | re.Pattern,
        timeout: float | None = None,
        inline_safe: bool = False,
    ) -> Callable[[str], list[re.Match]]:
        compiled = (
            pattern
            if isinstance(pattern, re.Pattern)
            else self.compile_pattern_sync(pattern)
        )
        match_timeout = timeout or self.default_timeout

        if inline_safe:

            def inline_safe_finditer(text: str) -> list[re.Match]:
                return list(compiled.finditer(text))

            return inline_safe_finditer

        def safe_finditer(text: str) -> list[re.Match]:
            future = shared_regex_executor().submit(
                lambda: list(compiled.finditer(text))
            )
            try:
                result = future.result(timeout=match_timeout)
                report_scan_success()
                return result
            except concurrent.futures.TimeoutError:
                future.cancel()
                report_scan_timeout()
                return []
            except Exception:
                return []

        return safe_finditer

    def create_async_safe_finditer_matcher(
        self,
        pattern: str | re.Pattern,
        timeout: float | None = None,
        inline_safe: bool = False,
    ) -> Callable[[str], list[re.Match]]:
        compiled = (
            pattern
            if isinstance(pattern, re.Pattern)
            else self.compile_pattern_sync(pattern)
        )
        match_timeout = timeout or self.default_timeout

        if inline_safe:

            def async_inline_finditer(text: str) -> list[re.Match]:
                return list(compiled.finditer(text))

            return async_inline_finditer

        sync_finder = self.create_safe_finditer_matcher(pattern, timeout=match_timeout)

        def async_safe_finditer(text: str) -> list[re.Match]:
            return sync_finder(text)

        return async_safe_finditer

    def batch_compile(
        self, patterns: list[str], validate: bool = True
    ) -> dict[str, re.Pattern]:
        compiled_patterns = {}
        for pattern in patterns:
            if validate:
                is_safe, reason = self.validate_pattern_safety(pattern)
                if not is_safe:
                    continue
            try:
                compiled_patterns[pattern] = self.compile_pattern(pattern)
            except re.error:
                continue
        return compiled_patterns

    def clear_cache(self) -> None:
        with self._lock:
            self._compiled_cache.clear()
            self._cache_order.clear()
