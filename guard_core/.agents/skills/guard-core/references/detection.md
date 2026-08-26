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
    enabled_categories=None,  # subset of the 19, None = all
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

## The 19 categories

`ALL_DETECTION_CATEGORIES` (`guard_core/handlers/suspatterns_handler.py`): `xss`, `sqli`, `dir_traversal`, `path_traversal`, `cmd_injection`, `file_inclusion`, `ldap`, `xml`, `ssrf`, `nosql`, `file_upload`, `template`, `http_split`, `sensitive_file`, `cms_probing`, `recon`, `proto_pollution`, `code_injection`, `deserialization`.

`deserialization` (CWE-502) matches Java (`rO0AB`), .NET `BinaryFormatter` (`AAEAAAD`) and Ruby `Marshal` (`BAh[Jv7bV]`) serialized payloads in their base64 wire form (`_DESERIALIZATION_JAVA_B64_RE`, `_DESERIALIZATION_DOTNET_B64_RE`, `_DESERIALIZATION_RUBY_B64_RE`, `guard_core/handlers/suspatterns_handler.py:291-294`), the raw XAML gadget marker `<ObjectDataProvider` (`guard_core/handlers/suspatterns_handler.py:2410`), and PHP (`O:`/`C:`/`E:`). Python pickle is matched two ways: the base64 marker `gASV`/`gAWV` (`_DESERIALIZATION_PICKLE_B64_RE`, `guard_core/handlers/suspatterns_handler.py:293`), and the raw (non-base64) protocol-0 `GLOBAL` opcode text itself, `c<module>\n<name>\n` (`_DESERIALIZATION_PICKLE_OS_GLOBAL_RE`, `_DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE`, `guard_core/handlers/suspatterns_handler.py:295-301`, wired into the category's pattern list at `:2394-2405`). Raw bytes are reachable: the request body is decoded with `body_bytes.decode("utf-8", errors="surrogateescape")` (`guard_core/_utils/penetration_detection.py:102`), which never rejects a byte, so non-UTF-8 pickle opcode bytes reach the patterns unchanged. `tests/test_sus_patterns/test_pickle_global_opcode_prefix_bypass.py` proves raw and binary-prefixed pickle payloads are detected through the real `detect_penetration_attempt` entry point across the request body, form body, multipart body, query parameter, and JSON body shapes.

`ssrf` also matches the IPv4-mapped IPv6 loopback bracket form (`http://[::ffff:127.0.0.1]/`) and a trailing-dot `localhost` (`http://localhost./`), alongside its existing dotted-quad, `localhost`, private/link-local-range, and cloud-metadata-alias coverage; `http://[::ffff:8.8.8.8]/` (a public address in the same bracket shape) stays unflagged.

## Request-value scan cap

`SecurityConfig.detection_max_scan_values` (default `512`, `ge=2`) bounds the total number of individual values -- query parameters, header values, JSON keys and leaf values, form fields, multipart parts, including JSON embedded within a single value -- scanned per request across the whole penetration-detection pass (`guard_core/_security_config_fields.py`). The budget is a per-request `contextvars.ContextVar` pair (`guard_core/_utils/detection_scan.py`), reset around each `detect_penetration_attempt` call. Each named value costs two scan units, one for its name and one for its value, so the minimum is `2`, not `1`. Once the cap is reached, remaining values in that request are not scanned, and a one-time `logger.warning` (per request) names the client IP, so the fail-open stays visible instead of silent.

Request parameter/field/key **names**, not only values, are scanned for injection patterns (`_scan_component_name` in `guard_core/_utils/detection_scan.py`, called from `_scan_query_params`, `_scan_headers`, `_scan_json_value`, `_scan_form_body`, and `_scan_multipart_body` in `guard_core/_utils/body_content_scan.py`): `?username[$ne]=admin`, `?__proto__[isAdmin]=true`, a JSON body key `"1;DROP TABLE x"`, or a multipart field named `__proto__[x]` are all detected via the name, even when the value itself is benign. An excluded header's name and value still get the Log4Shell JNDI shield (`ALWAYS_SCAN_HEADER_PATTERNS`, `guard_core/handlers/suspatterns_handler.py`, checked by `_scan_excluded_header_component` in `guard_core/_utils/body_content_scan.py`) rather than the full pipeline, preserving the excluded-header design.

Each has a default weight of `1.0` in `DETECTION_CATEGORY_WEIGHTS`; specific regex patterns override via `DETECTION_PATTERN_WEIGHT_OVERRIDES` (e.g. a bare `SELECT ... FROM` is down-weighted to 0.5 to reduce false positives).

## Preprocessing layers

`ContentPreprocessor.preprocess(content)` applies up to 7 decode/normalize layers before matching: Unicode normalization, URL-decode, HTML-entity decode, null-byte removal, whitespace normalization, attack-region-aware truncation to `detection_max_content_length`, plus opportunistic base64 / hex / Unicode-escape / SQL-comment stripping. Match against the preprocessed content, never raw.

## Semantic analysis

`SemanticAnalyzer.analyze(content)` returns a dict with `attack_probability` (per-category 0-1), `obfuscation` (bool), `code_injection_risk` (float), `threat_score`. Scoring is deterministic: keyword-overlap, Shannon entropy, encoding-layer count, obfuscation indicators. It is not machine learning and does not learn from traffic.

## ReDoS safety

`PatternCompiler.validate_pattern_safety(pattern, test_strings=None, max_content_length=None)` (`guard_core/detection_engine/compiler.py`) first rejects a pattern that hits a known-dangerous construct (`(.*)+`, `(.+)+`, nested quantifiers -- `_dangerous_construct_violation`) and one that fails to compile. Past that, it runs in one of two modes:

* With `test_strings` (the `add_pattern`/dynamic-rule/content-filter call sites): a broader structural pre-filter (`_first_structural_safety_violation`, flagging adjacent broad unbounded quantifiers, ambiguous optional tails in quantified groups, unreachable terminator scans, and ambiguous literal boundaries), then a timed probe of the pattern against `test_strings` inside a **killable subprocess** (`subprocess.run(..., timeout=2.0)`, never a thread the caller waits on), rejecting if any probe exceeds a 50ms-per-string budget.
* Without `test_strings` (the default, used to probe a pattern at a caller's real content-length cap): a timed cost arbiter (`_reach_probe_cost_verdict`) builds adversarial probes at four sizes (roughly 4k/8k/16k/32k characters), times each with `time.process_time()` in a killable subprocess (minimum of 5 samples, median drives the verdict), and rejects only if the growth-extrapolated cost at `max_content_length` exceeds 50ms; a structural hit supplies the rejection reason when the arbiter also rejects, but a structural hit measured under budget and linear does not reject on its own, and no probe being buildable forces fail-closed rejection.

This validation subprocess mechanism is unrelated to, and isolated from, the live-scan pool: built-in (compile-time-vetted, never run through `validate_pattern_safety` at runtime) patterns match directly via `pattern.search()` with no per-match timeout; only custom patterns added via `SusPatternsManager.add_pattern(pattern, custom=True)` run through the shared thread-pool safe-matcher (`shared_regex_executor()`, `guard_core/detection_engine/compiler.py`) with a timeout at match time. Four consecutive timeouts recycle the shared pool (stale workers shut down non-blocking) so one pathological pattern cannot wedge every worker. Separately, the enhanced-detection exception fallback (`_fallback_pattern_check`, `guard_core/_utils/detection_scan.py`) routes every pattern through the same bounded matchers the enhanced scan uses (`SusPatternsManager._check_regex_pattern`), so a pattern-level exception on the enhanced path no longer falls through to an unbounded `pattern.search()`.

## Scan-window bounded matchers

`guard_core.detection_engine.scan_window` (`bounded_search`, `bounded_finditer`) bounds the regex *scan window*, not the match length, for built-in patterns shaped `literal_prefix + unbounded_negated_class + terminator`. It locates every prefix and terminator occurrence with two linear `finditer` passes, then runs the pattern's own unmodified, uncapped regex only against the bounded span from each prefix candidate to the farthest reachable terminator, so neither an unbounded quantifier nor a `{0,N}` length cap is needed to stay linear, and outcome (matched or not) agrees with running the pattern unbounded. `_WINDOWED_PATTERN_FINDERS` (`guard_core/handlers/suspatterns_handler.py`) maps specific built-in pattern strings to a `prefix`/`terminator` pair wired through `bounded_finditer`; a pattern not in that mapping matches directly, uncapped.

## Tuning knobs (SecurityConfig)

`detection_max_content_length` (default 10000), `detection_compiler_timeout` (default 2.0s, range 0.1-10.0), `detection_threat_score_threshold` (default 1.0), `detection_max_scan_values` (default 512, `ge=2`; see [Request-value scan cap](#request-value-scan-cap) above), `enabled_detection_categories` (`frozenset[str]`, subset of the 19, defaults to all 19). `PatternCompiler.validate_pattern_safety`'s 50ms cost-arbiter budget is a hardcoded constant, not a config field; only `max_content_length` (the caller's real content-length cap) is passed in per call.

## Adding patterns

```python
ok = await SusPatternsManager.add_pattern(r"<script.*?>", custom=True)
```

Custom patterns are ReDoS-validated, compiled with `re.IGNORECASE | re.MULTILINE`, and (when Redis is enabled) persisted under the `patterns` key. `remove_pattern(pattern, custom=False)` removes them. Do not add unvetted patterns as built-in; custom patterns get the timeout safety path.
