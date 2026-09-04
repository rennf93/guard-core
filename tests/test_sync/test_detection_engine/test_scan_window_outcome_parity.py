import random
import re

import pytest

from guard_core.sync.detection_engine.scan_window import bounded_search

_TRIALS_PER_PATTERN = 5000
_LENGTH_RANGE = (20, 200)
_TOKEN_PROBABILITY = 0.35
_RAW_MATCH_RATE_FLOOR = 0.20


def _random_texts(tokens: list[str], chars: str, count: int, seed: int) -> list[str]:
    rng = random.Random(seed)
    texts = []
    for _ in range(count):
        target_length = rng.randint(*_LENGTH_RANGE)
        parts: list[str] = []
        total = 0
        while total < target_length:
            piece = (
                rng.choice(tokens)
                if rng.random() < _TOKEN_PROBABILITY
                else rng.choice(chars)
            )
            parts.append(piece)
            total += len(piece)
        texts.append("".join(parts))
    return texts


_SCRIPT_COMPILED = re.compile(r"<script[^>]*>[^<]*<\/script\s*>", re.IGNORECASE)
_SCRIPT_PREFIX = re.compile(r"<script", re.IGNORECASE)
_SCRIPT_TERMINATOR = re.compile(r"<\/script\s*>", re.IGNORECASE)
_SCRIPT_TOKENS = ["<script", "</script>", '"', "'", ">", " ", "x", "="]
_SCRIPT_CHARS = "<>/\" 'xa="

_DIR_TRAVERSAL_COMPILED = re.compile(r"\.\.;[^/\\]*[/\\]")
_DIR_TRAVERSAL_PREFIX = re.compile(r"\.\.;")
_DIR_TRAVERSAL_TERMINATOR = re.compile(r"[/\\]")
_DIR_TRAVERSAL_TOKENS = ["..;", "/", "\\", "x"]
_DIR_TRAVERSAL_CHARS = "..;/\\x"

_XML_COMPILED = re.compile(r"<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>", re.IGNORECASE)
_XML_PREFIX = re.compile(r"<!(?:ENTITY|DOCTYPE)", re.IGNORECASE)
_XML_TERMINATOR = re.compile(r">")
_XML_TOKENS = ["<!ENTITY", "<!DOCTYPE", "SYSTEM", ">", '"', "x"]
_XML_CHARS = '<!ENTITYDOCTPESYM> "x'

_FILE_INCLUSION_COMPILED = re.compile(
    r"=(?:https?|ftp):\/\/[^\s'\"<>]+\/[^\s'\"<>\/]*"
    r"\.(?:phtml|php[3-5]?|phar|jsp|aspx?|pl|py|txt|inc)"
    r"(?![a-zA-Z0-9])",
    re.IGNORECASE,
)
_FILE_INCLUSION_PREFIX = re.compile(r"=", re.IGNORECASE)
_FILE_INCLUSION_TERMINATOR = re.compile(r"(?![a-zA-Z0-9])", re.IGNORECASE)
_FILE_INCLUSION_TOKENS = [
    "=http://",
    "=https://",
    "=ftp://",
    "/",
    ".php",
    ".phtml",
    ".jsp",
    ".aspx",
    ".txt",
    ".inc",
    ".cgi",
    "evil",
    "com",
    "a",
    "b",
    "1",
]
_FILE_INCLUSION_CHARS = "=/.abc123AXZ "

_ASP_TEMPLATE_COMPILED = re.compile(r"<%[=#]?[^%]*(?:system|exec|eval)", re.IGNORECASE)
_ASP_TEMPLATE_PREFIX = re.compile(r"<%", re.IGNORECASE)
_ASP_TEMPLATE_TERMINATOR = re.compile(r"")
_ASP_TEMPLATE_TOKENS = ["<%", "<%=", "<%#", "%>", "system", "exec", "eval", "%"]
_ASP_TEMPLATE_CHARS = "<%=#>sxeacl "


@pytest.mark.parametrize(
    ("label", "compiled", "prefix", "terminator", "tokens", "chars", "seed"),
    [
        (
            "script",
            _SCRIPT_COMPILED,
            _SCRIPT_PREFIX,
            _SCRIPT_TERMINATOR,
            _SCRIPT_TOKENS,
            _SCRIPT_CHARS,
            1,
        ),
        (
            "dir_traversal",
            _DIR_TRAVERSAL_COMPILED,
            _DIR_TRAVERSAL_PREFIX,
            _DIR_TRAVERSAL_TERMINATOR,
            _DIR_TRAVERSAL_TOKENS,
            _DIR_TRAVERSAL_CHARS,
            2,
        ),
        (
            "xml_entity_system",
            _XML_COMPILED,
            _XML_PREFIX,
            _XML_TERMINATOR,
            _XML_TOKENS,
            _XML_CHARS,
            3,
        ),
        (
            "file_inclusion",
            _FILE_INCLUSION_COMPILED,
            _FILE_INCLUSION_PREFIX,
            _FILE_INCLUSION_TERMINATOR,
            _FILE_INCLUSION_TOKENS,
            _FILE_INCLUSION_CHARS,
            4,
        ),
        (
            "asp_template_injection",
            _ASP_TEMPLATE_COMPILED,
            _ASP_TEMPLATE_PREFIX,
            _ASP_TEMPLATE_TERMINATOR,
            _ASP_TEMPLATE_TOKENS,
            _ASP_TEMPLATE_CHARS,
            5,
        ),
    ],
)
def test_bounded_search_agrees_with_raw_search_on_random_text(
    label: str,
    compiled: re.Pattern,
    prefix: re.Pattern,
    terminator: re.Pattern,
    tokens: list[str],
    chars: str,
    seed: int,
) -> None:
    texts = _random_texts(tokens, chars, _TRIALS_PER_PATTERN, seed)

    raw_hits = 0
    outcome_mismatches = []
    span_mismatches = []
    for text in texts:
        raw = compiled.search(text)
        if raw is not None:
            raw_hits += 1
        bounded = bounded_search(text, compiled, prefix, terminator)
        if (raw is not None) != (bounded is not None):
            outcome_mismatches.append(text)
        elif raw is not None and bounded is not None and raw.span() != bounded.span():
            span_mismatches.append((text, raw.span(), bounded.span()))

    raw_match_rate = raw_hits / len(texts)
    assert raw_match_rate >= _RAW_MATCH_RATE_FLOOR, (
        f"{label}: raw matched only {raw_hits}/{len(texts)} ({raw_match_rate:.1%}) "
        f"trials, below the {_RAW_MATCH_RATE_FLOOR:.0%} floor; this alphabet no "
        f"longer exercises the pattern, so outcome parity below is not evidence "
        f"of anything (see the round-3 post-mortem: 0% raw match rate is how "
        f"round 2's broken fuzz reported clean)"
    )
    assert outcome_mismatches == [], (
        f"{label}: {len(outcome_mismatches)}/{len(texts)} outcome disagreements "
        f"(raw matched {raw_hits}/{len(texts)}, {raw_match_rate:.1%}), "
        f"first={outcome_mismatches[0]!r}"
    )
    assert span_mismatches == [], (
        f"{label}: {len(span_mismatches)}/{len(texts)} span disagreements "
        f"(raw matched {raw_hits}/{len(texts)}, {raw_match_rate:.1%}), "
        f"first={span_mismatches[0]!r}"
    )
