import re

_BINARY_ARTIFACT_RE = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f"
    r"\x80-\xa2\xa4\xa6-\xa9\xab-\xaf\xb4\xb6-\xb8\xbb-\xbf"
    r"\u0180-\u024f\ufffd\udc80-\udcff]"
)
_BINARY_DENSITY_RADIUS = 64
_BINARY_DENSITY_LIMIT = 4


def build_binary_prefix(content: str) -> list[int]:
    prefix = [0] * (len(content) + 1)
    count = 0
    filled = 0
    for match in _BINARY_ARTIFACT_RE.finditer(content):
        count += 1
        boundary = match.end()
        prefix[filled + 1 : boundary] = [count - 1] * (boundary - filled - 1)
        prefix[boundary] = count
        filled = boundary
    prefix[filled:] = [count] * (len(content) + 1 - filled)
    return prefix


def match_is_binary_dense(binary_prefix: list[int] | None, match: re.Match) -> bool:
    if binary_prefix is None:
        return False
    high = min(match.end() + _BINARY_DENSITY_RADIUS, len(binary_prefix) - 1)
    low = max(match.start() - _BINARY_DENSITY_RADIUS, 0)
    return binary_prefix[high] - binary_prefix[low] >= _BINARY_DENSITY_LIMIT
