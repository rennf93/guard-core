import re

from guard_core.sync.detection_engine.binary_prefix import _BINARY_ARTIFACT_RE

_ISLAND_RUN_RE = re.compile(
    "[\t\n\r\x20-\x7e\u00a1-\ud7ff\ue000-\ufffc\ufffe-\uffff\U00010000-\U0010ffff]+"
)

_BINARY_LIKE_ARTIFACT_RATIO = 0.2


def value_is_binary_like(content: str) -> bool:
    if not content:
        return False
    artifact_count = sum(1 for _ in _BINARY_ARTIFACT_RE.finditer(content))
    return artifact_count / len(content) >= _BINARY_LIKE_ARTIFACT_RATIO


def extract_binary_islands(content: str, min_run_length: int) -> list[str]:
    if min_run_length <= 1:
        return [content]
    return [
        run for run in _ISLAND_RUN_RE.findall(content) if len(run) >= min_run_length
    ]
