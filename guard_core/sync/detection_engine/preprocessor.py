import re
import unicodedata
from typing import Any


class ContentPreprocessor:
    def __init__(
        self,
        max_content_length: int = 10000,
        preserve_attack_patterns: bool = True,
        agent_handler: Any = None,
        correlation_id: str | None = None,
    ):
        self.max_content_length = max_content_length
        self.preserve_attack_patterns = preserve_attack_patterns
        self.agent_handler = agent_handler
        self.correlation_id = correlation_id

        self.attack_indicators = [
            r"<script",
            r"javascript:",
            r"on\w+=",
            r"SELECT\s+.{0,50}?\s+FROM",
            r"UNION\s+SELECT",
            r"\.\./",
            r"eval\s*\(",
            r"exec\s*\(",
            r"system\s*\(",
            r"<?php",
            r"<%",
            r"{{",
            r"{%",
            r"<iframe",
            r"<object",
            r"<embed",
            r"onerror\s*=",
            r"onload\s*=",
            r"\$\{",
            r"\\x[0-9a-fA-F]{2}",
            r"%[0-9a-fA-F]{2}",
        ]

        self.compiled_indicators = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.attack_indicators
        ]

    def _send_preprocessor_event(
        self,
        event_type: str,
        action_taken: str,
        reason: str,
        **kwargs: Any,
    ) -> None:
        if not self.agent_handler:
            return

        try:
            from datetime import datetime, timezone

            event = type(
                "SecurityEvent",
                (),
                {
                    "timestamp": datetime.now(timezone.utc),
                    "event_type": event_type,
                    "ip_address": "system",
                    "action_taken": action_taken,
                    "reason": reason,
                    "metadata": {
                        "component": "ContentPreprocessor",
                        "correlation_id": self.correlation_id,
                        **kwargs,
                    },
                },
            )()
            self.agent_handler.send_event(event)
        except Exception as e:
            import logging

            logging.getLogger("guard_core.sync.detection_engine").error(
                f"Failed to send preprocessor event to agent: {e}"
            )

    def normalize_unicode(self, content: str) -> str:
        normalized = unicodedata.normalize("NFKC", content)

        lookalikes = {
            "\u2044": "/",
            "\uff0f": "/",
            "\u29f8": "/",
            "\u0130": "I",
            "\u0131": "i",
            "\u200b": "",
            "\u200c": "",
            "\u200d": "",
            "\ufeff": "",
            "\u00ad": "",
            "\u034f": "",
            "\u180e": "",
            "\u2028": "\n",
            "\u2029": "\n",
            "\ue000": "",
            "\ufff0": "",
            "\u01c0": "|",
            "\u037e": ";",
            "\u2215": "/",
            "\u2216": "\\",
            "\uff1c": "<",
            "\uff1e": ">",
        }

        for char, replacement in lookalikes.items():
            normalized = normalized.replace(char, replacement)

        return normalized

    def remove_excessive_whitespace(self, content: str) -> str:
        content = re.sub(r"\s+", " ", content)
        content = content.strip()
        return content

    def extract_attack_regions(self, content: str) -> list[tuple[int, int]]:
        max_regions = min(100, self.max_content_length // 100)
        regions = []

        for indicator in self.compiled_indicators:
            import concurrent.futures

            def _find_all(pattern: re.Pattern, text: str) -> list[tuple[int, int]]:
                found: list[tuple[int, int]] = []
                for match in pattern.finditer(text):
                    if len(found) >= max_regions:
                        break
                    start = max(0, match.start() - 100)
                    end = min(len(text), match.end() + 100)
                    found.append((start, end))
                return found

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_find_all, indicator, content)
                try:
                    indicator_regions = future.result(timeout=0.5)
                    regions.extend(indicator_regions)
                except concurrent.futures.TimeoutError:
                    continue

            if len(regions) >= max_regions:
                break

        if regions:
            regions.sort()
            merged = [regions[0]]
            for start, end in regions[1:]:
                if start <= merged[-1][1]:
                    merged[-1] = (merged[-1][0], max(merged[-1][1], end))
                else:
                    merged.append((start, end))
            return merged[:max_regions]

        return []

    def _extract_and_concatenate_attack_regions(
        self, content: str, attack_regions: list[tuple[int, int]]
    ) -> str:
        result = ""
        remaining = self.max_content_length

        for start, end in attack_regions:
            chunk_len = min(end - start, remaining)
            result += content[start : start + chunk_len]
            remaining -= chunk_len
            if remaining <= 0:
                break

        return result

    def _add_non_attack_content(
        self,
        content: str,
        attack_regions: list[tuple[int, int]],
        result_parts: list[str],
        remaining: int,
    ) -> None:
        last_end = 0
        for start, end in attack_regions:
            if last_end < start and remaining > 0:
                chunk_len = min(start - last_end, remaining)
                result_parts.insert(0, content[last_end : last_end + chunk_len])
                remaining -= chunk_len
            last_end = end

    def _build_result_with_attack_regions_and_context(
        self, content: str, attack_regions: list[tuple[int, int]]
    ) -> str:
        attack_length = sum(end - start for start, end in attack_regions)
        result_parts = []
        remaining = self.max_content_length - attack_length

        for start, end in attack_regions:
            result_parts.append(content[start:end])

        self._add_non_attack_content(content, attack_regions, result_parts, remaining)

        return "".join(result_parts)

    def truncate_safely(self, content: str) -> str:
        if len(content) <= self.max_content_length:
            return content

        if not self.preserve_attack_patterns:
            return content[: self.max_content_length]

        attack_regions = self.extract_attack_regions(content)

        if not attack_regions:
            return content[: self.max_content_length]

        attack_length = sum(end - start for start, end in attack_regions)

        if attack_length >= self.max_content_length:
            return self._extract_and_concatenate_attack_regions(content, attack_regions)

        return self._build_result_with_attack_regions_and_context(
            content, attack_regions
        )

    def remove_null_bytes(self, content: str) -> str:
        content = content.replace("\x00", "")

        control_chars = "".join(chr(i) for i in range(32) if i not in (9, 10, 13))
        translator = str.maketrans("", "", control_chars)
        return content.translate(translator)

    def decode_common_encodings(self, content: str) -> str:
        max_decode_iterations = 3
        iterations = 0

        while iterations < max_decode_iterations:
            original = content

            try:
                import urllib.parse

                decoded = urllib.parse.unquote(content, errors="ignore")
                if decoded != content:
                    content = decoded
            except Exception as e:
                self._send_preprocessor_event(
                    event_type="decoding_error",
                    action_taken="decode_failed",
                    reason="Failed to URL decode content",
                    error=str(e),
                    error_type="url_decode",
                )

            try:
                import html

                decoded = html.unescape(content)
                if decoded != content:
                    content = decoded
            except Exception as e:
                self._send_preprocessor_event(
                    event_type="decoding_error",
                    action_taken="decode_failed",
                    reason="Failed to HTML decode content",
                    error=str(e),
                    error_type="html_decode",
                )

            if content == original:
                break

            iterations += 1

        return content

    def preprocess(self, content: str) -> str:
        if not content:
            return ""

        content = self.normalize_unicode(content)
        content = self.decode_common_encodings(content)
        content = self.remove_null_bytes(content)
        content = self.remove_excessive_whitespace(content)
        content = self.truncate_safely(content)

        return content

    def preprocess_batch(self, contents: list[str]) -> list[str]:
        return [self.preprocess(content) for content in contents]
