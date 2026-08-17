import asyncio
import concurrent.futures
import logging
import re
import threading
import time
from collections.abc import Callable

logger = logging.getLogger("guard_core.detection_engine.compiler")

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
            i += 1
            while i < len(pattern):
                if pattern[i] == "\\" and i + 1 < len(pattern):
                    i += 2
                    continue
                if pattern[i] == "]":
                    i += 1
                    break
                i += 1
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


def _find_group_end(stripped: str, start: int) -> int | None:
    depth = 1
    j = start + 1
    while j < len(stripped) and depth > 0:
        if stripped[j] == "(":
            depth += 1
        elif stripped[j] == ")":
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


def _outer_quantifier_len(stripped: str, k: int) -> int:
    if k < len(stripped) and stripped[k] in "*+":
        return 1
    if k < len(stripped) and stripped[k] == "{":
        end_brace = stripped.find("}", k)
        if end_brace != -1:
            brace_inner = stripped[k + 1 : end_brace]
            if "," in brace_inner and brace_inner.split(",")[1] == "":
                return end_brace - k + 1
    return 0


def _detect_nested_unbounded_quantifier(pattern: str) -> str | None:
    stripped = _strip_escapes_and_char_classes(pattern)
    i = 0
    while i < len(stripped):
        if stripped[i] != "(":
            i += 1
            continue
        j = _find_group_end(stripped, i)
        if j is None:
            i += 1
            continue
        inner = _normalize_group_inner(stripped[i + 1 : j - 1])
        if inner is None:
            i = j
            continue
        qlen = _outer_quantifier_len(stripped, j)
        if qlen > 0 and any(_branch_is_unbounded_single(b) for b in inner.split("|")):
            return stripped[i : j + qlen]
        i = j
    return None


class PatternCompiler:
    MAX_CACHE_SIZE = 1000

    def __init__(self, default_timeout: float = 5.0, max_cache_size: int = 1000):
        self.default_timeout = default_timeout
        self.max_cache_size = min(max_cache_size, 5000)
        self._compiled_cache: dict[str, re.Pattern] = {}
        self._cache_order: list[str] = []
        self._lock = asyncio.Lock()

    async def compile_pattern(
        self, pattern: str, flags: int = re.IGNORECASE | re.MULTILINE
    ) -> re.Pattern:
        cache_key = f"{pattern}:{flags}"

        if cache_key in self._compiled_cache:
            async with self._lock:
                if cache_key in self._compiled_cache:
                    self._cache_order.remove(cache_key)
                    self._cache_order.append(cache_key)
                    return self._compiled_cache[cache_key]

        async with self._lock:
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
        self, pattern: str | re.Pattern, timeout: float | None = None
    ) -> Callable[[str], re.Match | None]:
        compiled = (
            pattern
            if isinstance(pattern, re.Pattern)
            else self.compile_pattern_sync(pattern)
        )
        match_timeout = timeout or self.default_timeout

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
        self, pattern: str | re.Pattern, timeout: float | None = None
    ) -> Callable[[str], list[re.Match]]:
        compiled = (
            pattern
            if isinstance(pattern, re.Pattern)
            else self.compile_pattern_sync(pattern)
        )
        match_timeout = timeout or self.default_timeout

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

    async def batch_compile(
        self, patterns: list[str], validate: bool = True
    ) -> dict[str, re.Pattern]:
        compiled_patterns = {}
        for pattern in patterns:
            if validate:
                is_safe, reason = self.validate_pattern_safety(pattern)
                if not is_safe:
                    continue
            try:
                compiled_patterns[pattern] = await self.compile_pattern(pattern)
            except re.error:
                continue
        return compiled_patterns

    async def clear_cache(self) -> None:
        async with self._lock:
            self._compiled_cache.clear()
            self._cache_order.clear()
