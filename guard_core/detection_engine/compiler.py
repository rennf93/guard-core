import asyncio
import re
import time
from collections.abc import Callable


class TimeoutError(Exception):
    pass


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

        if test_strings is None:
            test_strings = [
                "a" * 10,
                "a" * 100,
                "a" * 1000,
                "x" * 50 + "y" * 50,
                "<" * 100 + ">" * 100,
            ]

        try:
            compiled = self.compile_pattern_sync(pattern)
            import concurrent.futures

            for test_str in test_strings:
                start_time = time.time()

                def _search(text: str = test_str) -> re.Match | None:
                    return compiled.search(text)

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(_search)
                    try:
                        future.result(timeout=0.1)
                    except concurrent.futures.TimeoutError:
                        return (
                            False,
                            f"Pattern timed out on test string of length "
                            f"{len(test_str)}",
                        )

                elapsed = time.time() - start_time
                if elapsed > 0.05:
                    return (
                        False,
                        f"Pattern timed out on test string of length {len(test_str)}",
                    )
        except Exception as e:
            return False, f"Pattern validation failed: {str(e)}"

        return True, "Pattern appears safe"

    def create_safe_matcher(
        self, pattern: str, timeout: float | None = None
    ) -> Callable[[str], re.Match | None]:
        compiled = self.compile_pattern_sync(pattern)
        match_timeout = timeout or self.default_timeout

        def safe_match(text: str) -> re.Match | None:
            import concurrent.futures

            def _search() -> re.Match | None:
                return compiled.search(text)

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_search)
                try:
                    return future.result(timeout=match_timeout)
                except concurrent.futures.TimeoutError:
                    future.cancel()
                    return None
                except Exception:
                    return None

        return safe_match

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
