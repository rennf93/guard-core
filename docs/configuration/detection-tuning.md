---

title: Detection Tuning
description: Guide to tuning guard-core's detection engine for optimal sensitivity vs performance tradeoffs
keywords: detection tuning, sensitivity, performance, false positives, guard-core
---

Detection Tuning
================

The detection engine's behavior is controlled by several `SecurityConfig` fields prefixed with `detection_`. This guide explains each field and how to tune them for different deployment scenarios.

Configuration Fields
--------------------

### `detection_compiler_timeout`

**Type**: `float` | **Default**: `2.0` | **Range**: 0.1 - 10.0

Maximum time in seconds for a single regex pattern match. Patterns that exceed this timeout are cancelled, preventing ReDoS attacks from consuming server resources.

| Value    | Tradeoff                                                     |
|----------|--------------------------------------------------------------|
| `0.5`    | Very aggressive. May cause false negatives on complex inputs.|
| `2.0`    | Balanced. Catches most attacks while limiting resource usage.|
| `5.0`    | Permissive. Better detection but higher latency risk.        |

### `detection_max_content_length`

**Type**: `int` | **Default**: `10000` | **Range**: 1000 - 100000

Maximum character count for content passed to the detection engine. Content exceeding this limit is truncated (with attack-preserving logic if enabled).

| Value     | Tradeoff                                                    |
|-----------|-------------------------------------------------------------|
| `3000`    | Fast processing. May miss attacks in large request bodies.  |
| `10000`   | Balanced for most APIs.                                     |
| `50000`   | Thorough scanning. Higher memory and CPU usage per request. |

### `detection_preserve_attack_patterns`

**Type**: `bool` | **Default**: `True`

When `True`, the truncation algorithm identifies attack-like regions in the content and preserves them in the truncated output, even if they fall beyond the `max_content_length` boundary. Set to `False` for simple left-truncation when performance is critical.

### `detection_semantic_threshold`

**Type**: `float` | **Default**: `0.7` | **Range**: 0.0 - 1.0

Minimum score from the `SemanticAnalyzer` to classify content as a threat. The semantic analyzer scores content across multiple attack types (XSS, SQL injection, command injection, path traversal, template injection).

| Value    | Tradeoff                                                     |
|----------|--------------------------------------------------------------|
| `0.3`    | Very sensitive. High detection rate but more false positives.|
| `0.7`    | Balanced. Good detection with low false positive rate.       |
| `0.9`    | Conservative. Only high-confidence semantic threats trigger. |

!!! info "Semantic vs Regex"
    Regex patterns provide definitive threat detection. Semantic analysis is a secondary layer that catches obfuscated or novel attacks. Lowering the semantic threshold increases the chance of catching evasion attempts but also increases false positives on legitimate content containing technical terms.

### `detection_anomaly_threshold`

**Type**: `float` | **Default**: `3.0` | **Range**: 1.0 - 10.0

Number of standard deviations from the mean execution time to flag a pattern as anomalous. This tracks performance anomalies, not security threats.

| Value    | Tradeoff                                                     |
|----------|--------------------------------------------------------------|
| `2.0`    | Sensitive anomaly detection. More alerts on normal variance. |
| `3.0`    | Standard. Catches significant deviations.                    |
| `5.0`    | Only extreme outliers trigger alerts.                        |

### `detection_slow_pattern_threshold`

**Type**: `float` | **Default**: `0.1` | **Range**: 0.01 - 1.0

Execution time in seconds above which a pattern is considered slow. Slow patterns are reported in performance diagnostics and may indicate ReDoS vulnerability.

### `detection_monitor_history_size`

**Type**: `int` | **Default**: `1000` | **Range**: 100 - 10000

Number of recent performance metrics retained in the `PerformanceMonitor`. Larger values provide better statistical analysis but consume more memory.

### `detection_max_tracked_patterns`

**Type**: `int` | **Default**: `1000` | **Range**: 100 - 5000

Maximum number of unique patterns tracked by the performance monitor. When exceeded, the oldest pattern's stats are evicted. Also controls the `PatternCompiler` cache size.

___

Tuning Profiles
---------------

### High Security

For applications handling sensitive data where false negatives are unacceptable:

```python
SecurityConfig(
    detection_compiler_timeout=5.0,
    detection_max_content_length=50000,
    detection_preserve_attack_patterns=True,
    detection_semantic_threshold=0.3,
    detection_anomaly_threshold=2.0,
    detection_slow_pattern_threshold=0.05,
)
```

### Balanced (Default)

Suitable for most production deployments:

```python
SecurityConfig(
    detection_compiler_timeout=2.0,
    detection_max_content_length=10000,
    detection_preserve_attack_patterns=True,
    detection_semantic_threshold=0.7,
    detection_anomaly_threshold=3.0,
    detection_slow_pattern_threshold=0.1,
)
```

### High Performance

For high-throughput APIs where latency is critical:

```python
SecurityConfig(
    detection_compiler_timeout=0.5,
    detection_max_content_length=3000,
    detection_preserve_attack_patterns=False,
    detection_semantic_threshold=0.9,
    detection_anomaly_threshold=5.0,
    detection_slow_pattern_threshold=0.05,
    detection_monitor_history_size=100,
    detection_max_tracked_patterns=200,
)
```

### Detection Disabled

For routes where detection is not needed (e.g., health checks):

```python
SecurityConfig(
    enable_penetration_detection=False,
)
```

Or per-route via decorators:

```python
@security.advanced(enable_suspicious_detection=False)
async def health_check():
    return {"status": "ok"}
```

___

Diagnostics
-----------

The `SusPatternsManager` provides runtime diagnostics:

```python
from guard_core.handlers.suspatterns_handler import sus_patterns_handler

stats = await sus_patterns_handler.get_performance_stats()
# {
#     "summary": {"total_executions": 15432, "avg_execution_time": 0.003, ...},
#     "slow_patterns": [...],
#     "problematic_patterns": [...]
# }

status = await sus_patterns_handler.get_component_status()
# {"compiler": True, "preprocessor": True, "semantic_analyzer": True, "performance_monitor": True}
```

Use these diagnostics to identify patterns that need optimization or replacement.
