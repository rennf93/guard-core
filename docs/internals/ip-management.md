---

title: IP Management
description: IPBanManager internals, IP allow/block logic, CIDR support, and country-based filtering in guard-core
keywords: ip banning, ip management, blacklist, whitelist, cidr, guard-core
---

IP Management
=============

Guard-core provides layered IP access control through the `IPBanManager` handler and utility functions in `guard_core.utils`. This page covers the internal mechanics that adapter developers need to understand.

IPBanManager
------------

`IPBanManager` is a singleton that manages a set of banned IPs using a dual-layer storage strategy: a local `TTLCache` for fast lookups, and optional Redis for distributed state.

### Singleton Pattern

```python
class IPBanManager:
    _instance = None

    def __new__(cls) -> "IPBanManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.banned_ips = TTLCache(maxsize=10000, ttl=3600)
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None
        return cls._instance
```

The singleton is pre-instantiated as `ip_ban_manager` at module level.

### Storage

| Layer      | Backend                          | TTL        | Capacity |
|------------|----------------------------------|------------|----------|
| Local      | `cachetools.TTLCache`            | 3600s      | 10,000   |
| Distributed| Redis (via `RedisManager`)       | Per-ban    | Unlimited|

### Key Methods

**`ban_ip(ip, duration, reason="threshold_exceeded")`**

Stores `(ip, expiry_timestamp)` in both local cache and Redis. Also fires a ban event to the agent handler if configured.

**`unban_ip(ip)`**

Removes the IP from both local cache and Redis.

**`is_ip_banned(ip) -> bool`**

Lookup order:

1. Check local `TTLCache`. If present and not expired, return `True`. If expired, remove and continue.
2. Check Redis. If present and not expired, promote to local cache and return `True`. If expired, delete from Redis.
3. Return `False`.

**`reset()`**

Clears both the local cache and all `{redis_prefix}banned_ips:*` keys from Redis.

### Initialization

```python
await ip_ban_manager.initialize_redis(redis_handler)
await ip_ban_manager.initialize_agent(agent_handler)
```

Both are optional. Without Redis, bans are local to the process. Without an agent handler, ban/unban events are not sent.

___

IP Allow/Block Logic
--------------------

The function `is_ip_allowed()` in `guard_core.utils` implements the global IP evaluation chain. It is called by `IpSecurityCheck` for requests without route-level overrides.

### Evaluation Order

```mermaid
flowchart TD
    START["is_ip_allowed()"]
    BL{"1. IP in blacklist?"}
    WL{"2. IP not in whitelist?"}
    CC{"3. Country blocked?"}
    CL{"4. Cloud provider blocked?"}
    ALLOW["return True"]
    DENY["return False"]

    START --> BL
    BL -- Yes --> DENY
    BL -- No --> WL
    WL -- Yes --> DENY
    WL -- No --> CC
    CC -- Yes --> DENY
    CC -- No --> CL
    CL -- Yes --> DENY
    CL -- No --> ALLOW
```

### Blacklist Check

```python
async def _check_blacklist(ip_addr, ip, config) -> bool:
    for blocked in config.blacklist:
        if "/" in blocked:
            if ip_addr in ip_network(blocked, strict=False):
                return False  # blocked
        elif ip == blocked:
            return False  # blocked
    return True  # not blocked
```

Supports both individual IPs and CIDR ranges (e.g., `10.0.0.0/8`).

### Whitelist Check

```python
async def _check_whitelist(ip_addr, ip, config) -> bool:
    if config.whitelist:
        for allowed in config.whitelist:
            if "/" in allowed:
                if ip_addr in ip_network(allowed, strict=False):
                    return True
            elif ip == allowed:
                return True
        return False  # whitelist exists but IP not in it
    return True  # no whitelist, all allowed
```

!!! info "Whitelist Semantics"
    When `config.whitelist` is `None`, the whitelist is disabled and all IPs pass. When it is an empty list `[]`, no IPs pass. This distinction matters for adapter developers exposing configuration.

### Country Check

Uses the `GeoIPHandler` protocol to resolve the country code for an IP, then checks it against `config.blocked_countries` and `config.whitelist_countries`.

### Cloud Provider Check

Delegates to `CloudManager.is_cloud_ip()` to check if the IP belongs to a blocked cloud provider.

___

Client IP Extraction
--------------------

```python
async def extract_client_ip(
    request: GuardRequest,
    config: SecurityConfig,
    agent_handler: AgentHandlerProtocol | None = None,
) -> str
```

### Logic

1. If `request.client_host` is `None`, return `"unknown"`.
2. Get the connecting IP from `request.client_host`.
3. Get `X-Forwarded-For` header value.
4. If no trusted proxies are configured, log a spoofing warning (if `X-Forwarded-For` is present) and return the connecting IP.
5. If the connecting IP is not a trusted proxy, log a spoofing warning and return the connecting IP.
6. If the connecting IP is a trusted proxy, extract the client IP from `X-Forwarded-For` at position `0` (leftmost), respecting `config.trusted_proxy_depth`.

### Trusted Proxy Evaluation

```python
def _is_trusted_proxy(connecting_ip, trusted_proxies) -> bool:
    for proxy in trusted_proxies:
        if "/" in proxy:
            if ip_address(connecting_ip) in ip_network(proxy, strict=False):
                return True
        elif connecting_ip == proxy:
            return True
    return False
```

### Spoofing Detection

When an `X-Forwarded-For` header is received from an untrusted source, guard-core logs a warning and fires an agent event with `event_type="suspicious_request"` and `action_taken="spoofing_detected"`. The request is still processed using the connecting IP.

___

Route-Level IP Access
---------------------

The `check_route_ip_access()` helper in `guard_core.core.checks.helpers` evaluates IP access for decorator-configured routes:

```python
async def check_route_ip_access(client_ip, route_config, middleware) -> bool | None:
```

**Returns**:

- `False` -- IP is denied (blacklisted, not whitelisted, or country-blocked).
- `True` -- IP is explicitly allowed.
- `None` -- No route-level IP rules apply; fall through to global rules.

**Evaluation**:

1. `RouteConfig.ip_blacklist` -- deny if matched.
2. `RouteConfig.ip_whitelist` -- allow if matched, deny if list exists but IP is not in it.
3. Country access via `RouteConfig.blocked_countries` and `RouteConfig.whitelist_countries` using `GeoIPHandler`.
