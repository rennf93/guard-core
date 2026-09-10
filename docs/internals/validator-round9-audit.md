---
title: Validator adversarial review, round 9
description: Findings and verification record for the validator adjacency security review
---

# Validator adversarial review, round 9

The review started from `fix/validator-adjacency-and-test-instruments` after
`54a93b31` and `6c313f6e`. The working tree also contains the user's changes.
Passing focused tests is not the acceptance criterion: the final synchronized
source must pass the full suite, Detection Gate, and quality checks.

## Confirmed findings and regression coverage

| Area | Confirmed failure | Regression coverage |
| --- | --- | --- |
| Repeat alphabets | A restrictive Unicode tail such as `[^\u2603]` defeated homogeneous ASCII probes. Small and fixed finite repeat counts also escaped the large-repeat threshold. | `test_redos_repeat_alphabet.py`, `test_redos_helper_branches.py` |
| Repeated groups | `(?:[a-m][n-z])*(?:[a-m][n-z])*X` was accepted. Searches on repeated `an` grew from about 0.027s at 400 characters to 1.63s at 1600 on the review host. | `test_redos_repeat_units.py`, `test_redos_repeat_alphabet.py` |
| Reaching prefixes | Alternatives, captures, optional tokens, and lookarounds hid costly repeats. Examples include `\Axf?(?<!x)a+a+$` and `\A(?=f.o)fooa+a+$`. | `test_redos_repeat_prefix.py`, `test_redos_repeat_alphabet.py` |
| Assertion constraints | Nested pending lookaheads could produce no reaching probe while validation still accepted the pattern. | `test_redos_repeat_prefix.py`, `test_redos_repeat_alphabet.py` |
| Validation resources | Stray verification needed killable execution and fail-closed child handling. Probe construction needed explicit allocation and candidate budgets. Character predicates needed bounded caching. | `test_redos_stray_chooser.py`, `test_redos_reach_probe.py`, `test_redos_intervals.py`, prefix and batching tests |
| Case folding | ASCII ignore-case handling incorrectly added ASCII equivalents for non-ASCII Kelvin sign, long s, and dotless i. | `test_redos_intervals.py` |
| Templates and XML | Padding caps lost detections; repeated openers and rematching exposed costly scans. XML also had URL-boundary and earliest-match span errors. | `test_template_matcher_security.py`, `test_xxe_matcher_security.py`, `test_xml_xxe_corpus.py` |
| Upload filenames | Quote floods, extension handling, uppercase escape forms, and matcher spans exposed correctness or cost failures. | `test_upload_matcher_security.py` |
| Pickle markers | Invalid earlier segments could hide a later valid marker; identifier folding and match boundaries also differed. | `test_pickle_finder_security.py` |
| Path and shell patterns | Redundant path-prefix matching exceeded the CPU budget. | `test_path_extension_regex_regression.py`, `test_shell_flag_security.py` |
| SQL injection and LDAP | Overlapping whitespace repeats caused quadratic failure paths. The first LDAP rewrite still failed direct scaling despite passing the validator, and was corrected. | `test_builtin_pattern_rewrites.py` |
| Monitoring | Recomputing variance for observations that cannot exceed the configured nonnegative threshold exceeded the CPU budget under load. | `test_monitor.py` |
| Test instruments | Missing or crashed timing children could be represented by zero measurements. Formatting failures during synchronization were not propagated reliably. | `test_timing_harness.py`, `test_unasync_check_gate.py` |
| Embedded prose validation | The CMS prose pattern exhausted its shared validation deadline while measuring 12,140 candidates. Expanding its three optional trailing path segments preserves its language and match spans while reducing construction to 42 candidates. The shared deadline and exhaustive candidate measurement remain unchanged. | `test_embedded_prose_pattern.py`, existing built-in validator gate |
| Grammar test duration | A single test executed 10,404 grammar combinations. Parameterizing the 36 outer atom pairs preserves all combinations while allowing the per-test runtime limit to apply to each group of 289 cases. | `test_redos_cost_arbiter.py` |
| Acceptance expectations | Two unanchored repeated patterns were still labeled safe in the tests. The full timing gate measured approximately fourfold cost growth per input doubling and correctly rejected them. Tests now require rejection of the original forms and acceptance of anchored forms. | `test_custom_redos_hardening.py` |

Test names above refer to the async sources under `tests/test_sus_patterns` or
`tests/test_detection`; `make sync` generates their sync counterparts.

## Construction and timing invariants

Repeated group units remain paired with prefixes from their own repeat sites.
Optional bodies are visited to collect internal repeat sites. An omitted optional
path represents later repeats only when neither the body, incoming constraints,
nor the enclosing continuation can distinguish the consumed optional text.
Assertion witness construction remains exhaustive within its budgets. Unknown
parser operations are conservative. Unresolved prefixes before remaining repeats
reject validation.

Construction limits bound individual strings, aggregate state text, repeat-site
pairs, and expanded candidates. Exceeding a limit rejects the pattern. Probe
execution uses a shared deadline and killable child processes. Deduplication stores
length-framed SHA-256 digests instead of retaining every large probe string.
Batching must preserve every distinct candidate, its size-specific timing rows,
the configured content cap, and the shared deadline.

A passing validator is empirical screening, not a mathematical proof of linear
execution for every input. Direct adversarial tests and the detection corpus are
separate acceptance requirements.

## Verification record

The following checks have completed during this round:

- Fresh Daybreak adversarial review reproduced the repeated-group and prefix
  failures. Its follow-up review found no concrete bypass in the optional-path
  optimization, and its batching review identified excessive process-startup cost.
- Construction preflight: all 128 raw built-ins completed within the configured
  deadlines. The largest case generated 12,140 builders.
- Prefix construction regression tests: 113 passed, one Python-version syntax
  skip, with 100% branch coverage across the six new construction modules.
- Reach, class-intersection, and stray-selection helpers: 203 passed, one skip,
  with 100% branch coverage across those three modules.
- Detection corpus comparison against merge base
  `f1121ca479027253a1d99aac02c5ebaf7dff157b`: no new misses, false positives,
  per-mechanism regressions, or errors.
- Component smoke checks passed on Python 3.10.19, 3.11.14, 3.12.12, 3.13.11,
  and 3.14.3. These are not full suite runs on those interpreters.

These checks preceded the final synchronized verification below. Earlier passing
runs and focused results alone do not close the acceptance requirements.

### September 9 continuation

- Corrected the diagnostic indexing: the 12,140-candidate pattern was the CMS
  prose entry in the raw-safe corpus, not metadata entry 83 in the complete
  built-in table.
- Embedded prose equivalence: 18 parameterized tests passed, covering all six
  affected pattern families, exact spans, separators, Unicode, newline behavior,
  and trailing-segment boundaries.
- CMS validator measurement after the rewrite: 42 candidates; validation passed
  in approximately 7.4 seconds on the review host.
- `make sync`, `make quality`, and all pre-commit hooks passed after the changes.
- Synchronized full suite on Python 3.10: 21,300 passed, six skipped, 825
  deselected in 1,411 seconds, with warnings as errors and a 180-second per-test
  limit. The initial run failed only the coverage requirement at 99.97%.
- Added ordinary parser-boundary tests for the remaining five lines and four
  branches. All 30 focused tests passed; combined coverage reached 100% across
  26,159 statements and 8,180 branches. Production-file hashes remained identical
  to those used by the completed full suite.
- Refreshed both sides of the 990-case detection corpus comparison. The baseline
  snapshot matched all 1,220 files from the recorded merge-base commit. The gate
  passed with no new misses, false positives, per-mechanism regressions, or errors.
- Final quality checks passed after the additional tests. Both standard and
  CPU-load timing gates are complete.
- The first standard timing run was stopped after two acceptance-expectation
  failures and 352 passes. Corrected expectations passed all four focused checks.
  The timing grammar matrix was also split across the same 36 outer atom pairs,
  retaining all 324 combinations and their measurements. No production behavior
  or validator thresholds changed in response to these test failures.
- Final synchronized Detection Gate: 897 passed, 21,324 deselected, in 3,648.40
  seconds.
- The original full CPU-load Detection Gate recorded 896 passes and one failure
  in 5,136.47 seconds. Two repeated upload diagnostics exposed timing
  variability; each covered 10 repetitions, 20 helper runs, and 240 shape cases,
  and each recorded one failure.
- The upload timing harness now retains the same 20 calls per pattern and shape,
  alternating size order across five rounds. Its 50 ms absolute guard uses
  per-size medians; its growth guard uses the minimum of the five fixed samples
  for each size against the existing 10 ms floor and 3x limit. This follows the
  lower-bound guidance for repeated measurements in Python's
  [`timeit`](https://docs.python.org/3/library/timeit.html#timeit.Timer.repeat)
  documentation. Shape-set, malformed-data, and exact-boundary checks are
  deterministic and retain raw measurements.
- The fresh upload diagnostics completed 20 repetitions, 40 helper runs, and
  480 shape cases with zero failures. The two upload test modules also passed
  normally with 30 tests in 2.10 seconds and under 12 workers with 30 tests in
  14.85 seconds (`/tmp/guard-round9-upload-followup.log` and
  `/tmp/guard-round9-upload-load-followup.log`). All 371 production-file hashes
  remain unchanged, and the manifest still contains 113 proposed paths with
  five exclusions.
- Final full CPU-load Detection Gate: 897 passed, 21,342 deselected, in 5,257.33
  seconds (1:27:37). The 12-worker runner cleaned up successfully. This closes
  the round's functional, standard timing, and CPU-load acceptance gates.
