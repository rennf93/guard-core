import re
from collections.abc import Callable

from guard_core.sync.detection_engine._redos_ambiguous_tail import (
    _detect_ambiguous_optional_tail_in_quantified_group,
)
from guard_core.sync.detection_engine._redos_literal_in_wildcard import (
    _detect_ambiguous_literal_boundary,
)
from guard_core.sync.detection_engine._redos_structure import (
    _detect_adjacent_broad_unbounded_quantifiers,
    _detect_nested_unbounded_quantifier,
)
from guard_core.sync.detection_engine._redos_unreachable_terminator import (
    _detect_unreachable_terminator_scan,
)

_STRUCTURAL_SAFETY_CHECKS: tuple[tuple[Callable[[str], str | None], str], ...] = (
    (
        _detect_nested_unbounded_quantifier,
        "Pattern contains nested unbounded quantifier: ",
    ),
    (
        _detect_adjacent_broad_unbounded_quantifiers,
        "Pattern contains adjacent broad unbounded quantifiers: ",
    ),
    (
        _detect_unreachable_terminator_scan,
        "Pattern contains a broad scan whose terminator cannot be reached by "
        "repeating its own prefix: ",
    ),
    (
        _detect_ambiguous_literal_boundary,
        "Pattern contains a quantified class that can absorb the mandatory "
        "literal immediately following it: ",
    ),
    (
        _detect_ambiguous_optional_tail_in_quantified_group,
        "Pattern contains an ambiguous optional tail inside an unbounded "
        "quantified group: ",
    ),
)


def _first_structural_safety_violation(pattern: str) -> str | None:
    for check, message in _STRUCTURAL_SAFETY_CHECKS:
        finding = check(pattern)
        if finding is not None:
            return f"{message}{finding}"
    return None


_INNER_UNBOUNDED_QUANTIFIER = r"(?:\*|\+|\{[0-9]+,\})"
_OUTER_UNBOUNDED_QUANTIFIER = r"(?:\+|\{[0-9]+,\})"
_DANGEROUS_CONSTRUCT_PATTERNS = (
    rf"\(\.{_INNER_UNBOUNDED_QUANTIFIER}\){_OUTER_UNBOUNDED_QUANTIFIER}",
    rf"\([^)]*{_INNER_UNBOUNDED_QUANTIFIER}\){_OUTER_UNBOUNDED_QUANTIFIER}",
    rf"(?:\.{_INNER_UNBOUNDED_QUANTIFIER}){{2,}}",
)


def _dangerous_construct_violation(pattern: str) -> str | None:
    for dangerous in _DANGEROUS_CONSTRUCT_PATTERNS:
        if re.search(dangerous, pattern):
            return f"Pattern contains dangerous construct: {dangerous}"
    return None
