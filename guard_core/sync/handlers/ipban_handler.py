import ipaddress
import logging
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from cachetools import TTLCache

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class _ObservableTTLCache(TTLCache):
    def __init__(
        self,
        maxsize: int,
        ttl: float,
        on_evict: Callable[[], None],
    ) -> None:
        super().__init__(maxsize=maxsize, ttl=ttl)
        self._on_evict = on_evict

    def popitem(self) -> tuple[Any, Any]:
        item = super().popitem()
        self._on_evict()
        return item


class IPBanManager:
    LOCAL_CACHE_TTL_CAP_SECONDS = 3600
    _EVICTION_LOG_EVERY = 100

    _instance: "IPBanManager | None" = None
    banned_ips: TTLCache
    banned_networks: list[tuple[_Network, float]]
    evictions_count: int
    logger: logging.Logger
    config: Any = None
    redis_handler: Any = None
    agent_handler: Any = None

    def __new__(cls: type["IPBanManager"]) -> "IPBanManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.evictions_count = 0
            cls._instance.logger = logging.getLogger("guard_core.sync.handlers.ipban")
            cls._instance.banned_ips = _ObservableTTLCache(
                maxsize=10000,
                ttl=cls.LOCAL_CACHE_TTL_CAP_SECONDS,
                on_evict=cls._instance._on_eviction,
            )
            cls._instance.banned_networks = []
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None
        return cls._instance

    def _on_eviction(self) -> None:
        self.evictions_count += 1
        if self.evictions_count % self._EVICTION_LOG_EVERY == 0:
            self.logger.warning(
                "IP ban cache full; %d entries evicted (silent overflow)",
                self.evictions_count,
            )

    def initialize_redis(self, redis_handler: Any) -> None:
        self.redis_handler = redis_handler

    def initialize_agent(self, agent_handler: Any) -> None:
        self.agent_handler = agent_handler

    def _assert_positive_duration(self, duration: int) -> None:
        if duration <= 0:
            raise ValueError(f"ban duration must be positive, got {duration}")

    def _assert_local_cap(self, duration: int) -> None:
        if duration > self.LOCAL_CACHE_TTL_CAP_SECONDS:
            raise ValueError(
                f"ban duration {duration}s exceeds local cache capacity "
                f"{self.LOCAL_CACHE_TTL_CAP_SECONDS}s and Redis is unavailable"
            )

    def _ban_cidr(self, ip: str, duration: int) -> None:
        try:
            network = ipaddress.ip_network(ip, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR network {ip!r}: {e}") from e

        if self.redis_handler is None:
            self._assert_local_cap(duration)
            self.banned_networks.append((network, time.time() + duration))
            return

        try:
            self.redis_handler.set_key(
                "banned_networks",
                str(network),
                str(time.time() + duration),
                ttl=duration,
            )
        except Exception:
            if duration > self.LOCAL_CACHE_TTL_CAP_SECONDS:
                raise
            self.banned_networks.append((network, time.time() + duration))

    def _ban_exact_ip(self, ip: str, duration: int, reason: str) -> None:
        try:
            ipaddress.ip_address(ip)
        except ValueError as e:
            raise ValueError(f"Invalid IP address {ip!r}: {e}") from e

        if self.redis_handler is None:
            self._assert_local_cap(duration)

        expiry = time.time() + duration
        self.banned_ips[ip] = expiry

        if self.redis_handler:
            self.redis_handler.set_key("banned_ips", ip, str(expiry), ttl=duration)

        if self.agent_handler:
            self._send_ban_event(ip, duration, reason)

    def ban_ip(
        self, ip: str, duration: int, reason: str = "threshold_exceeded"
    ) -> None:
        self._assert_positive_duration(duration)
        if "/" in ip:
            self._ban_cidr(ip, duration)
        else:
            self._ban_exact_ip(ip, duration, reason)

    def _send_ban_event(self, ip: str, duration: int, reason: str) -> None:
        from guard_core.sync.core.events.event_types import EVENT_IP_BANNED

        try:
            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=EVENT_IP_BANNED,
                ip_address=ip,
                action_taken="banned",
                reason=reason,
                metadata={"duration": duration},
            )
            self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error("Failed to send ban event to agent: %s", e)

    def unban_ip(self, ip: str) -> None:
        if ip in self.banned_ips:
            del self.banned_ips[ip]

        if self.redis_handler:
            self.redis_handler.delete("banned_ips", ip)

        if self.agent_handler:
            self._send_unban_event(ip)

    def _send_unban_event(self, ip: str) -> None:
        from guard_core.sync.core.events.event_types import EVENT_IP_UNBANNED

        try:
            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=EVENT_IP_UNBANNED,
                ip_address=ip,
                action_taken="unbanned",
                reason="dynamic_rule_whitelist",
                metadata={"action": "unban"},
            )
            self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error("Failed to send unban event to agent: %s", e)

    def _check_network_cache(
        self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address, now: float
    ) -> bool:
        active: list[tuple[_Network, float]] = []
        hit = False
        for network, expiry in self.banned_networks:
            if expiry <= now:
                continue
            active.append((network, expiry))
            if not hit and addr.version == network.version and addr in network:
                hit = True
        self.banned_networks = active
        return hit

    def _check_redis_exact(self, ip: str, current_time: float) -> bool:
        expiry = self.redis_handler.get_key("banned_ips", ip)
        if not expiry:
            return False
        expiry_time = float(expiry)
        if current_time <= expiry_time:
            self.banned_ips[ip] = expiry_time
            return True
        self.redis_handler.delete("banned_ips", ip)
        return False

    def is_ip_banned(self, ip: str) -> bool:
        current_time = time.time()

        if ip in self.banned_ips:
            if current_time > self.banned_ips[ip]:
                del self.banned_ips[ip]
                return False
            return True

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False

        if self._check_network_cache(addr, current_time):
            return True

        if self.redis_handler:
            return self._check_redis_exact(ip, current_time)

        return False

    def reset(self) -> None:
        self.banned_ips.clear()
        self.banned_networks.clear()
        if self.redis_handler:
            with self.redis_handler.get_connection() as conn:
                keys = conn.keys(
                    f"{self.redis_handler.config.redis_prefix}banned_ips:*"
                )
                if keys:
                    conn.delete(*keys)


ip_ban_manager = IPBanManager()


def reset_global_state() -> None:
    global ip_ban_manager
    ip_ban_manager = IPBanManager()
