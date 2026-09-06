import bisect
import re
from collections.abc import Iterator

from guard_core.handlers._suspatterns_sources import (
    _XML_XXE_PUBLIC_EXTERNAL_DTD_RE,
)

_XML_XXE_PUBLIC_EXTERNAL_DTD_COMPILED_RE = re.compile(
    _XML_XXE_PUBLIC_EXTERNAL_DTD_RE, re.IGNORECASE
)
_XML_XXE_DOCTYPE_RE = re.compile(r"<!DOCTYPE", re.IGNORECASE)
_XML_XXE_PUBLIC_RE = re.compile(r"PUBLIC", re.IGNORECASE)
_XML_XXE_QUOTE_CHARS = frozenset("\"'")
_XML_XXE_SCHEME_RE = re.compile(r"https?://", re.IGNORECASE)
_XML_XXE_W3_ORG_RE = re.compile(r"(?:www\.)?w3\.org/", re.IGNORECASE)
_XML_XXE_CLASS12_BOUNDARY_RE = re.compile(r"[>\[]")
_XML_XXE_CLASS3_BOUNDARY_RE = re.compile(r"[\"'>]")


def _xml_xxe_first_at_or_after(sorted_positions: list[int], floor: int) -> int | None:
    idx = bisect.bisect_left(sorted_positions, floor)
    return sorted_positions[idx] if idx < len(sorted_positions) else None


def _xml_xxe_last_before(
    sorted_positions: list[int], ceiling_exclusive: int
) -> int | None:
    idx = bisect.bisect_left(sorted_positions, ceiling_exclusive)
    return sorted_positions[idx - 1] if idx > 0 else None


def _xml_xxe_scheme_completion_end(
    text: str,
    scheme_start: int,
    class12_boundaries: list[int],
    class3_boundaries: list[int],
) -> int | None:
    if scheme_start == 0 or text[scheme_start - 1] not in _XML_XXE_QUOTE_CHARS:
        return None
    scheme_match = _XML_XXE_SCHEME_RE.match(text, scheme_start)
    if scheme_match is None:
        return None
    scheme_end = scheme_match.end()
    if _XML_XXE_W3_ORG_RE.match(text, scheme_end) is not None:
        return None
    class3_stop_idx = bisect.bisect_left(class3_boundaries, scheme_end + 1)
    if class3_stop_idx >= len(class3_boundaries):
        return None
    quote2 = class3_boundaries[class3_stop_idx]
    if text[quote2] == ">":
        return None
    class4_stop_idx = bisect.bisect_left(class12_boundaries, quote2 + 1)
    if class4_stop_idx >= len(class12_boundaries):
        return None
    final_boundary = class12_boundaries[class4_stop_idx]
    return final_boundary if text[final_boundary] == ">" else None


def _xml_xxe_valid_quote_completions(
    text: str, class12_boundaries: list[int], class3_boundaries: list[int]
) -> tuple[list[int], dict[int, int]]:
    quote_positions: list[int] = []
    quote_to_final_gt: dict[int, int] = {}
    for scheme_match in _XML_XXE_SCHEME_RE.finditer(text):
        final_gt = _xml_xxe_scheme_completion_end(
            text, scheme_match.start(), class12_boundaries, class3_boundaries
        )
        if final_gt is not None:
            quote_pos = scheme_match.start() - 1
            quote_positions.append(quote_pos)
            quote_to_final_gt[quote_pos] = final_gt
    return quote_positions, quote_to_final_gt


def _xml_xxe_public_run_bounds(
    class12_boundaries: list[int], public_pos: int, text_len: int
) -> tuple[int, int]:
    run_idx = bisect.bisect_right(class12_boundaries, public_pos)
    run_start = class12_boundaries[run_idx - 1] + 1 if run_idx > 0 else 0
    run_end = (
        class12_boundaries[run_idx] if run_idx < len(class12_boundaries) else text_len
    )
    return run_start, run_end


def _xml_xxe_candidate_span(
    doctype_positions: list[int],
    quote_positions: list[int],
    quote_to_final_gt: dict[int, int],
    class12_boundaries: list[int],
    public_pos: int,
    text_len: int,
) -> tuple[int, int] | None:
    run_start, run_end = _xml_xxe_public_run_bounds(
        class12_boundaries, public_pos, text_len
    )
    doctype_before = _xml_xxe_last_before(doctype_positions, public_pos - 9)
    if doctype_before is None or doctype_before < run_start:
        return None
    quote1 = _xml_xxe_first_at_or_after(quote_positions, public_pos + 8)
    if quote1 is None or quote1 >= run_end:
        return None
    return doctype_before, quote_to_final_gt[quote1]


_XmlXxePrecomputed = tuple[list[int], list[int], list[int], list[int], dict[int, int]]


def _xml_xxe_precompute(text: str) -> _XmlXxePrecomputed | None:
    doctype_positions = [m.start() for m in _XML_XXE_DOCTYPE_RE.finditer(text)]
    public_positions = [m.start() for m in _XML_XXE_PUBLIC_RE.finditer(text)]
    if not doctype_positions or not public_positions:
        return None
    class12_boundaries = [
        m.start() for m in _XML_XXE_CLASS12_BOUNDARY_RE.finditer(text)
    ]
    class3_boundaries = [m.start() for m in _XML_XXE_CLASS3_BOUNDARY_RE.finditer(text)]
    quote_positions, quote_to_final_gt = _xml_xxe_valid_quote_completions(
        text, class12_boundaries, class3_boundaries
    )
    if not quote_positions:
        return None
    return (
        doctype_positions,
        public_positions,
        class12_boundaries,
        quote_positions,
        quote_to_final_gt,
    )


def _xml_xxe_public_external_dtd_finditer(
    text: str, compiled: re.Pattern
) -> Iterator[re.Match]:
    precomputed = _xml_xxe_precompute(text)
    if precomputed is None:
        return
    (
        doctype_positions,
        public_positions,
        class12_boundaries,
        quote_positions,
        quote_to_final_gt,
    ) = precomputed

    last_end = 0
    for public_pos in public_positions:
        if public_pos < last_end:
            continue
        span = _xml_xxe_candidate_span(
            doctype_positions,
            quote_positions,
            quote_to_final_gt,
            class12_boundaries,
            public_pos,
            len(text),
        )
        if span is None:
            continue
        doctype_before, final_gt = span
        match = compiled.match(text, doctype_before, final_gt + 1)
        if match is not None:
            yield match
            last_end = match.end()
