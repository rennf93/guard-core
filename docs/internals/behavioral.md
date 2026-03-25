---

title: Behavioral Analysis
description: BehaviorTracker and BehavioralProcessor internals for usage monitoring, return pattern detection, and action enforcement in guard-core
keywords: behavioral analysis, behavior tracking, usage rules, return patterns, guard-core
---

Behavioral Analysis
===================

Guard-core provides behavioral analysis through two components: the `BehaviorTracker` handler that stores and evaluates behavioral data, and the `BehavioralProcessor` core module that integrates tracking into the middleware pipeline.

BehaviorRule
------------

```python
class BehaviorRule:
    def __init__(
        self,
        rule_type: Literal["usage", "return_pattern", "frequency"],
        threshold: int,
        window: int = 3600,
        pattern: str | None = None,
        action: Literal["ban", "log", "throttle", "alert"] = "log",
        custom_action: Callable | None = None,
    ): ...
```

| Field           | Type                                     | Description                                     |
|-----------------|------------------------------------------|-------------------------------------------------|
| `rule_type`     | `"usage" \| "return_pattern" \| "frequency"` | When the rule is evaluated                     |
| `threshold`     | `int`                                    | Number of occurrences before triggering         |
| `window`        | `int`                                    | Time window in seconds                          |
| `pattern`       | `str \| None`                            | Pattern for `return_pattern` rules              |
| `action`        | `"ban" \| "log" \| "throttle" \| "alert"` | Action to take when threshold is exceeded       |
| `custom_action` | `Callable \| None`                       | Override function `(client_ip, endpoint_id, details)` |

### Rule Types

**`usage`** and **`frequency`**: Track how many times a client IP calls a specific endpoint within the window.

**`return_pattern`**: Track how many times a response matches a pattern for a specific client IP and endpoint.

### Return Pattern Formats

| Format           | Example                       | Matches                                      |
|------------------|-------------------------------|----------------------------------------------|
| `status:{code}`  | `status:404`                  | Response status code                         |
| `json:{path}`    | `json:error.code=="AUTH_FAIL"`| JSON field value via dot-path traversal       |
| `regex:{pattern}`| `regex:error.*failed`         | Regex match against response body (case-insensitive) |
| Plain string     | `unauthorized`                | Substring match in response body (case-insensitive) |

___

BehaviorTracker
---------------

### Storage

**In-memory**: `defaultdict(lambda: defaultdict(list))` mapping `endpoint_id -> client_ip -> list[timestamp]`.

**Redis**: Keys like `behavior:usage:{endpoint_id}:{client_ip}:{timestamp}` with TTL equal to the rule window.

### Key Methods

**`track_endpoint_usage(endpoint_id, client_ip, rule) -> bool`**

Records a usage event and returns `True` if the count exceeds `rule.threshold` within `rule.window`.

**`track_return_pattern(endpoint_id, client_ip, response, rule) -> bool`**

Checks if the response matches `rule.pattern`, records the event if it does, and returns `True` if the count exceeds the threshold.

### Action Execution

```python
await tracker.apply_action(rule, client_ip, endpoint_id, details)
```

**Active mode** actions:

| Action     | Behavior                                                   |
|------------|-----------------------------------------------------------|
| `ban`      | Calls `ip_ban_manager.ban_ip(client_ip, 3600, "behavioral_violation")` |
| `log`      | Logs a warning                                             |
| `throttle` | Logs a warning (throttling is informational; rate limiting handles enforcement) |
| `alert`    | Logs at CRITICAL level                                     |
| Custom     | Calls `rule.custom_action(client_ip, endpoint_id, details)` |

**Passive mode**: All actions are logged with a `[PASSIVE MODE]` prefix instead of being executed.

___

BehavioralProcessor
-------------------

The processor integrates behavioral tracking into the middleware pipeline. It is called at two points in the request lifecycle:

### Usage Rules (Pre-Handler)

```python
await processor.process_usage_rules(request, client_ip, route_config)
```

Iterates over `route_config.behavior_rules` where `rule_type` is `"usage"` or `"frequency"`. For each rule that exceeds its threshold, emits a `decorator_violation` event and applies the rule's action.

### Return Rules (Post-Handler)

```python
await processor.process_return_rules(request, response, client_ip, route_config)
```

Iterates over rules where `rule_type` is `"return_pattern"`. Checks if the response matches the rule's pattern, and if the threshold is exceeded, emits an event and applies the action.

### Endpoint ID Resolution

```python
def get_endpoint_id(self, request: GuardRequest) -> str
```

Resolves the endpoint identifier from the request:

1. If `request.state.guard_endpoint_id` exists, returns that value directly.
2. Otherwise, falls back to `"{method}:{url_path}"`.

___

Configuration via Decorators
-----------------------------

Behavioral rules are attached to routes through the `SecurityDecorator`:

```python
from guard_core.decorators import SecurityDecorator
from guard_core.handlers.behavior_handler import BehaviorRule

security = SecurityDecorator(config)

@security.behavioral(rules=[
    BehaviorRule(
        rule_type="usage",
        threshold=100,
        window=300,
        action="throttle",
    ),
    BehaviorRule(
        rule_type="return_pattern",
        threshold=10,
        window=60,
        pattern="status:429",
        action="ban",
    ),
])
async def my_endpoint():
    ...
```
