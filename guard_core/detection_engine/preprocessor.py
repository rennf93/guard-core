import binascii
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
            r"<\?php",
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
            r"`",
            r"\$\(",
            r"[;&|]",
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        ]

        self.compiled_indicators = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.attack_indicators
        ]

    _BASE64_RE = re.compile(
        r"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/][\r\n]*){12,}={0,2}(?![A-Za-z0-9+/=])"
    )
    _BASE64_WHITESPACE_RE = re.compile(r"[\r\n]+")
    _GZIP_MAGIC = b"\x1f\x8b"
    _MAX_GUNZIP_OUTPUT_BYTES = 8192
    _MAX_GUNZIP_ATTEMPTS_PER_PASS = 8
    _HEX_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
    _HEX_LITERAL_RE = re.compile(r"0[xX][0-9a-fA-F]+")
    _UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")
    _PERCENT_U_ESCAPE_RE = re.compile(r"%u([0-9a-fA-F]{4})", re.IGNORECASE)
    _PERCENT_BYTE_RUN_RE = re.compile(r"(?:%[0-9a-fA-F]{2})+")
    _SQL_BLOCK_COMMENT_STRIP_RE = re.compile(
        r"(?<!\w)/\*(?!!)(.*?)\*/|/\*(?!!)(.*?)\*/(?!\w)", re.DOTALL
    )
    _SQL_LINE_COMMENT_MARKER_RE = re.compile(r"--|#")

    async def _send_preprocessor_event(
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
            await self.agent_handler.send_event(event)
        except Exception as e:
            import logging

            logging.getLogger("guard_core.detection_engine").error(
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
            "\uff1b": ";",
            "\uff5c": "|",
            "\uff06": "&",
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

    def _build_result_with_attack_regions_and_context(
        self, content: str, attack_regions: list[tuple[int, int]]
    ) -> str:
        attack_length = sum(end - start for start, end in attack_regions)
        gap_budget = self.max_content_length - attack_length
        result_parts: list[str] = []
        last_end = 0

        for start, end in attack_regions:
            if last_end < start and gap_budget > 0:
                gap_len = start - last_end
                if gap_len <= gap_budget:
                    result_parts.append(content[last_end:start])
                    gap_budget -= gap_len
                else:
                    chunk_len = gap_budget - 1
                    if chunk_len > 0:
                        result_parts.append(content[last_end : last_end + chunk_len])
                    result_parts.append(" ")
                    gap_budget = 0
            result_parts.append(content[start:end])
            last_end = end

        if last_end < len(content) and gap_budget > 0:
            tail_len = min(len(content) - last_end, gap_budget)
            result_parts.append(content[last_end : last_end + tail_len])

        return "".join(result_parts)

    _TRUNCATION_SAMPLE_WINDOWS = 11

    def _sample_windows(self, content: str) -> str:
        num_windows = self._TRUNCATION_SAMPLE_WINDOWS
        window_size = max(1, self.max_content_length // num_windows)
        last_start = len(content) - window_size
        stride = last_start / (num_windows - 1)
        result = "".join(
            content[start : start + window_size]
            for start in (round(stride * i) for i in range(num_windows))
        )
        remaining = self.max_content_length - len(result)
        if remaining > 0:
            result += content[-remaining:]
        return result[: self.max_content_length]

    def truncate_safely(self, content: str) -> str:
        if len(content) <= self.max_content_length:
            return content

        if not self.preserve_attack_patterns:
            return content[: self.max_content_length]

        attack_regions = self.extract_attack_regions(content)

        if not attack_regions:
            return self._sample_windows(content)

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

    _PRINTABLE_ASCII_RATIO_THRESHOLD = 0.5
    _MAX_REPLACEMENT_CHAR_RATIO = 0.2

    def _is_hex_literal(self, token: str) -> bool:
        return bool(self._HEX_LITERAL_RE.fullmatch(token))

    def _printable_ascii_ratio(self, text: str) -> float:
        if not text:
            return 0.0
        printable_count = sum(1 for char in text if 0x20 <= ord(char) <= 0x7E)
        return printable_count / len(text)

    def _replacement_char_ratio(self, text: str) -> float:
        if not text:
            return 0.0
        return text.count("�") / len(text)

    def _bounded_gunzip(self, raw: bytes) -> bytes | None:
        if raw[:2] != self._GZIP_MAGIC:
            return None
        import zlib

        try:
            decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
            return decompressor.decompress(raw, self._MAX_GUNZIP_OUTPUT_BYTES)
        except (zlib.error, OSError):
            return None

    def _decode_base64_candidates(
        self, content: str, gunzip_attempts_left: list[int] | None = None
    ) -> str:
        import base64

        if gunzip_attempts_left is None:
            gunzip_attempts_left = [self._MAX_GUNZIP_ATTEMPTS_PER_PASS]

        def _replace(match: re.Match[str]) -> str:
            token = match.group(0)
            if self._is_hex_literal(token):
                return token
            cleaned = self._BASE64_WHITESPACE_RE.sub("", token)
            padding = (4 - len(cleaned) % 4) % 4
            padded = cleaned + "=" * padding
            try:
                raw = base64.b64decode(padded, validate=True)
            except (ValueError, binascii.Error):
                return token
            if raw[:2] == self._GZIP_MAGIC and gunzip_attempts_left[0] > 0:
                gunzip_attempts_left[0] -= 1
                gunzipped = self._bounded_gunzip(raw)
                if gunzipped is not None:
                    raw = gunzipped
            try:
                decoded = raw.decode("utf-8")
            except UnicodeDecodeError:
                decoded = raw.decode("utf-8", errors="replace")
                if (
                    self._replacement_char_ratio(decoded)
                    > self._MAX_REPLACEMENT_CHAR_RATIO
                ):
                    return token
            if (
                self._printable_ascii_ratio(decoded)
                >= self._PRINTABLE_ASCII_RATIO_THRESHOLD
            ):
                return decoded
            return token

        return self._BASE64_RE.sub(_replace, content)

    def _decode_hex_escapes(self, content: str) -> str:
        def _replace(match: re.Match[str]) -> str:
            try:
                return chr(int(match.group(1), 16))
            except ValueError:
                return match.group(0)

        return self._HEX_ESCAPE_RE.sub(_replace, content)

    def _decode_unicode_escapes(self, content: str) -> str:
        def _replace(match: re.Match[str]) -> str:
            try:
                return chr(int(match.group(1), 16))
            except ValueError:
                return match.group(0)

        return self._UNICODE_ESCAPE_RE.sub(_replace, content)

    def _decode_percent_u_escapes(self, content: str) -> str:
        def _replace(match: re.Match[str]) -> str:
            try:
                return chr(int(match.group(1), 16))
            except ValueError:
                return match.group(0)

        return self._PERCENT_U_ESCAPE_RE.sub(_replace, content)

    _OVERLONG_LEAD_SPECS: dict[int, tuple[int, int, int, int]] = {
        0xC0: (2, 0x1F, 0x80, 0xBF),
        0xC1: (2, 0x1F, 0x80, 0xBF),
        0xE0: (3, 0x0F, 0x80, 0x9F),
        0xF0: (4, 0x07, 0x80, 0x8F),
    }

    def _decode_overlong_sequence_at(
        self, raw: bytes, index: int
    ) -> tuple[str, int] | None:
        spec = self._OVERLONG_LEAD_SPECS.get(raw[index])
        if spec is None or index + spec[0] > len(raw):
            return None
        sequence_length, lead_mask, first_continuation_min, first_continuation_max = (
            spec
        )
        continuations = raw[index + 1 : index + sequence_length]
        if not first_continuation_min <= continuations[0] <= first_continuation_max:
            return None
        if any(not 0x80 <= byte <= 0xBF for byte in continuations[1:]):
            return None
        codepoint = raw[index] & lead_mask
        for byte in continuations:
            codepoint = (codepoint << 6) | (byte & 0x3F)
        return chr(codepoint), sequence_length

    def _lenient_overlong_utf8_decode(self, raw: bytes) -> str:
        chars: list[str] = []
        index = 0
        length = len(raw)
        while index < length:
            overlong = self._decode_overlong_sequence_at(raw, index)
            if overlong is not None:
                char, consumed = overlong
                chars.append(char)
                index += consumed
            elif raw[index] < 0x80:
                chars.append(chr(raw[index]))
                index += 1
            else:
                index += 1
        return "".join(chars)

    def _decode_overlong_utf8_percent_runs(self, content: str) -> str:
        def _replace(match: re.Match[str]) -> str:
            run = match.group()
            raw = bytes(int(run[i + 1 : i + 3], 16) for i in range(0, len(run), 3))
            try:
                raw.decode("utf-8")
            except UnicodeDecodeError:
                return self._lenient_overlong_utf8_decode(raw)
            return run

        return self._PERCENT_BYTE_RUN_RE.sub(_replace, content)

    def _strip_sql_comments(self, content: str) -> str:
        def _replace_block_comment(match: re.Match[str]) -> str:
            body = match.group(1) if match.group(1) is not None else match.group(2)
            return f" {body} "

        content = self._SQL_BLOCK_COMMENT_STRIP_RE.sub(_replace_block_comment, content)
        content = self._SQL_LINE_COMMENT_MARKER_RE.sub(" ", content)
        return content

    async def decode_common_encodings(self, content: str) -> str:
        max_decode_iterations = 16
        iterations = 0
        gunzip_attempts_left = [self._MAX_GUNZIP_ATTEMPTS_PER_PASS]

        while iterations < max_decode_iterations:
            original = content

            content = self._decode_overlong_utf8_percent_runs(content)

            try:
                import urllib.parse

                decoded = urllib.parse.unquote(content, errors="ignore")
                if decoded != content:
                    content = decoded
            except Exception as e:
                await self._send_preprocessor_event(
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
                await self._send_preprocessor_event(
                    event_type="decoding_error",
                    action_taken="decode_failed",
                    reason="Failed to HTML decode content",
                    error=str(e),
                    error_type="html_decode",
                )

            content = self._decode_percent_u_escapes(content)
            content = self._decode_hex_escapes(content)
            content = self._decode_unicode_escapes(content)
            content = self.normalize_unicode(content)
            content = self._decode_base64_candidates(content, gunzip_attempts_left)

            if content == original:
                break

            iterations += 1

        content = self._strip_sql_comments(content)
        return content

    async def preprocess(self, content: str) -> str:
        if not content:
            return ""

        content = self.normalize_unicode(content)
        content = await self.decode_common_encodings(content)
        content = self.remove_null_bytes(content)
        content = self.remove_excessive_whitespace(content)
        content = self.truncate_safely(content)

        return content

    def preprocess_signal_preserving(self, content: str) -> str:
        if not content:
            return ""

        content = self.normalize_unicode(content)
        return self.truncate_safely(content)

    async def preprocess_batch(self, contents: list[str]) -> list[str]:
        return [await self.preprocess(content) for content in contents]
