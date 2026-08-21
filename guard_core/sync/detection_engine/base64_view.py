import base64
import binascii
import re
from typing import Any

_RUN_FLOOR = 12

SHORT_BASE64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{4,}")
MAX_SHORT_BASE64_TOKEN_LENGTH = _RUN_FLOOR - 1
SHORT_BASE64_MARKER_CHARS = frozenset("${}#")
MAX_SHORT_BASE64_CANDIDATES = 20000
MAX_SHORT_BASE64_SCAN_BYTES = 2_000_000
PRINTABLE_RATIO_THRESHOLD = 0.95


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable_count = sum(1 for char in text if char.isprintable())
    return printable_count / len(text)


def _decode_token(token: str) -> str | None:
    if len(token) > MAX_SHORT_BASE64_TOKEN_LENGTH:
        return None
    padding = (4 - len(token) % 4) % 4
    try:
        decoded_bytes = base64.b64decode(token + "=" * padding, validate=True)
    except (ValueError, binascii.Error):
        return None
    try:
        return decoded_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _is_qualifying_fragment(text: str) -> bool:
    if _printable_ratio(text) < PRINTABLE_RATIO_THRESHOLD:
        return False
    return any(char in SHORT_BASE64_MARKER_CHARS for char in text)


def _decode_candidate(token: str) -> str | None:
    decoded = _decode_token(token)
    if decoded is None or not _is_qualifying_fragment(decoded):
        return None
    return decoded


def build_short_base64_additive_view(preprocessor: Any, content: str) -> str:
    if not content:
        return ""

    content = content[:MAX_SHORT_BASE64_SCAN_BYTES]
    content = preprocessor.normalize_unicode(content)
    content = preprocessor.truncate_safely(content)

    decoded_fragments: list[str] = []
    attempts = 0
    for match in SHORT_BASE64_TOKEN_RE.finditer(content):
        if attempts >= MAX_SHORT_BASE64_CANDIDATES:
            break
        attempts += 1
        decoded = _decode_candidate(match.group(0))
        if decoded is not None:
            decoded_fragments.append(decoded)

    return "\n".join(decoded_fragments)
