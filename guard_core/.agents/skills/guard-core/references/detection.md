# Detection Engine

`guard_core.detection_engine` exposes four components, orchestrated by `SusPatternsManager` (`guard_core/handlers/suspatterns_handler.py`).

## Public entry point

```python
from guard_core.handlers.suspatterns_handler import SusPatternsManager

result = await SusPatternsManager().detect(
    content=user_input,
    ip_address=request.client_host or "unknown",
    context="query_param",  # one of the context zones
    correlation_id=None,
    enabled_categories=None,  # subset of the 18, None = all
)
```

`context` filters which categories run. Valid zones: `query_param`, `header`, `url_path`, `request_body`, `unknown`. Each category maps to a frozenset of zones via `CATEGORY_CONTEXT_MAP`; a category runs only when its zones include the supplied context. `unknown` is the catch-all.

## detect() return shape

`dict[str, Any]` with at least: `is_threat: bool`, `threat_score`, `threats` (list of regex + semantic threat dicts), `regex_threats`, `semantic_threats`, `matched_patterns`, `timeouts`, `execution_time_ms`, `detection_method` (`"enhanced"` when a `PatternCompiler` is wired, else `"legacy"`).

For a boolean + pattern-name result, use `detect_pattern_match(content, ip_address, context, correlation_id) -> tuple[bool, str | None]`.

## DetectionResult

`guard_core.detection_result.DetectionResult` is a lightweight dataclass:

```python
@dataclass
class DetectionResult:
    is_threat: bool
    trigger_info: str
    threat_categories: list[str] = field(default_factory=list)
    threat_scores: dict[str, float] = field(default_factory=dict)
```

## The 18 categories

`ALL_DETECTION_CATEGORIES` (`guard_core/handlers/suspatterns_handler.py`): `xss`, `sqli`, `dir_traversal`, `path_traversal`, `cmd_injection`, `file_inclusion`, `ldap`, `xml`, `ssrf`, `nosql`, `file_upload`, `template`, `http_split`, `sensitive_file`, `cms_probing`, `recon`, `proto_pollution`, `code_injection`.

Each has a default weight of `1.0` in `DETECTION_CATEGORY_WEIGHTS`; specific regex patterns override via `DETECTION_PATTERN_WEIGHT_OVERRIDES` (e.g. a bare `SELECT ... FROM` is down-weighted to 0.5 to reduce false positives).

## Preprocessing layers

`ContentPreprocessor.preprocess(content)` applies up to 7 decode/normalize layers before matching: Unicode normalization, URL-decode, HTML-entity decode, null-byte removal, whitespace normalization, attack-region-aware truncation to `detection_max_content_length`, plus opportunistic base64 / hex / Unicode-escape / SQL-comment stripping. Match against the preprocessed content, never raw.

## Semantic analysis

`SemanticAnalyzer.analyze(content)` returns a dict with `attack_probability` (per-category 0-1), `obfuscation` (bool), `code_injection_risk` (float), `threat_score`. Scoring is deterministic: keyword-overlap, Shannon entropy, encoding-layer count, obfuscation indicators. It is not machine learning and does not learn from traffic.

## ReDoS safety

`PatternCompiler.validate_pattern_safety(pattern, test_strings)` rejects a pattern when any probe exceeds 50ms execution or hits known dangerous constructs (`(.*)+`, `(.+)+`, nested quantifiers). Validation runs on a dedicated single-worker executor, isolated from the live-scan pool. Built-in (compile-time-vetted) patterns match directly via `pattern.search()` with no per-match timeout; only custom patterns added via `SusPatternsManager.add_pattern(pattern, custom=True)` run through the shared thread-pool safe-matcher with a timeout. Four consecutive timeouts recycle the shared pool (stale workers shut down non-blocking) so one pathological pattern cannot wedge every worker.

## Tuning knobs (SecurityConfig)

`detection_max_content_length` (default 10000), `detection_compiler_timeout` (default 5.0s), `detection_validation_timeout` (default 1.0s), `detection_threat_score_threshold`, `detection_enabled_categories` (subset of the 18), `detection_max_pattern_length`.

## Adding patterns

```python
ok = await SusPatternsManager.add_pattern(r"<script.*?>", custom=True)
```

Custom patterns are ReDoS-validated, compiled with `re.IGNORECASE | re.MULTILINE`, and (when Redis is enabled) persisted under the `patterns` key. `remove_pattern(pattern, custom=False)` removes them. Do not add unvetted patterns as built-in; custom patterns get the timeout safety path.