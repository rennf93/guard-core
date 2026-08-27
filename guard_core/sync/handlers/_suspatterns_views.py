import time
from typing import Any

from guard_core.sync.handlers._suspatterns_regex import (
    _resolve_pattern_weight,
    _sanitize_for_reporting,
    _SusPatternsRegexMixin,
)
from guard_core.sync.handlers._suspatterns_sources import (
    _CTX_PATH_TRAVERSAL,
    _PATH_TRAVERSAL_DECODED_SHAPE_RE,
)
from guard_core.sync.handlers._suspatterns_state import _DetectionState


class _SusPatternsViewsMixin(_SusPatternsRegexMixin):
    def _check_raw_view_patterns(
        self,
        content: str,
        ip_address: str,
        context: str,
        correlation_id: str | None,
        enabled_categories: set[str] | None,
        state: _DetectionState,
    ) -> tuple[list[dict], list[str], list[str]]:
        preprocessor = state.preprocessor
        if not preprocessor:
            return [], [], []

        raw_view_content = preprocessor.preprocess_signal_preserving(content)
        return self._check_regex_patterns(
            raw_view_content,
            ip_address,
            correlation_id,
            context,
            enabled_categories,
            state=state,
            raw_view_only=True,
        )

    def _check_decoded_view_path_traversal(
        self,
        processed_content: str,
        content: str,
        context: str,
        enabled_categories: set[str] | None,
        state: _DetectionState,
    ) -> dict[str, Any] | None:
        preprocessor = state.preprocessor
        if not preprocessor:
            return None
        if self._normalize_context(context) not in _CTX_PATH_TRAVERSAL:
            return None
        if (
            enabled_categories is not None
            and "path_traversal" not in enabled_categories
        ):
            return None

        pattern_start = time.monotonic()
        raw_view_content = preprocessor.preprocess_signal_preserving(content)
        decoded_matches = list(
            _PATH_TRAVERSAL_DECODED_SHAPE_RE.finditer(processed_content)
        )
        raw_count = len(_PATH_TRAVERSAL_DECODED_SHAPE_RE.findall(raw_view_content))
        if len(decoded_matches) <= raw_count:
            return None

        match = decoded_matches[0]
        return {
            "type": "regex",
            "pattern": _PATH_TRAVERSAL_DECODED_SHAPE_RE.pattern,
            "match": _sanitize_for_reporting(match.group()),
            "position": match.start(),
            "execution_time": time.monotonic() - pattern_start,
            "category": "path_traversal",
            "weight": _resolve_pattern_weight(
                _PATH_TRAVERSAL_DECODED_SHAPE_RE.pattern, "path_traversal"
            ),
        }

    def _check_url_decoded_view_patterns(
        self,
        content: str,
        ip_address: str,
        context: str,
        correlation_id: str | None,
        enabled_categories: set[str] | None,
        state: _DetectionState,
        *,
        precomputed_decoded: str | None = None,
        precomputed_decode_budget_exhausted: bool = False,
    ) -> tuple[list[dict], list[str], list[str], bool]:
        preprocessor = state.preprocessor
        if not preprocessor:
            return [], [], [], False

        if precomputed_decoded is not None:
            url_decoded_view_content = preprocessor.truncate_safely(precomputed_decoded)
            decode_budget_exhausted_flag = precomputed_decode_budget_exhausted
        else:
            decode_budget_exhausted: list[bool] = [False]
            url_decoded_view_content = (
                preprocessor.preprocess_url_decoded_newline_preserving(
                    content, decode_budget_exhausted
                )
            )
            decode_budget_exhausted_flag = decode_budget_exhausted[0]

        threats, matched, timeouts = self._check_regex_patterns(
            url_decoded_view_content,
            ip_address,
            correlation_id,
            context,
            enabled_categories,
            state=state,
            url_decoded_view_only=True,
        )
        return threats, matched, timeouts, decode_budget_exhausted_flag

    def _check_short_base64_additive_view_patterns(
        self,
        content: str,
        ip_address: str,
        context: str,
        correlation_id: str | None,
        enabled_categories: set[str] | None,
        state: _DetectionState,
    ) -> tuple[list[dict], list[str], list[str]]:
        preprocessor = state.preprocessor
        if not preprocessor:
            return [], [], []
        if self._normalize_context(context) not in ("request_body", "query_param"):
            return [], [], []

        additive_view_content = preprocessor.preprocess_short_base64_additive_view(
            content
        )
        if not additive_view_content:
            return [], [], []

        return self._check_regex_patterns(
            additive_view_content,
            ip_address,
            correlation_id,
            context,
            enabled_categories,
            state=state,
        )
