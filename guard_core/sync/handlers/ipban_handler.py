import logging
import time
from datetime import datetime, timezone
from typing import Any

from cachetools import TTLCache


class IPBanManager:
    _instance = None
    banned_ips: TTLCache
    redis_handler: Any = None
    agent_handler: Any = None

    def __new__(cls: type["IPBanManager"]) -> "IPBanManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.banned_ips = TTLCache(maxsize=10000, ttl=3600)
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None
        return cls._instance

    def initialize_redis(self, redis_handler: Any) -> None:
        self.redis_handler = redis_handler

    def initialize_agent(self, agent_handler: Any) -> None:
        self.agent_handler = agent_handler

    def ban_ip(
        self, ip: str, duration: int, reason: str = "threshold_exceeded"
    ) -> None:
        expiry = time.time() + duration
        self.banned_ips[ip] = expiry

        if self.redis_handler:
            self.redis_handler.set_key("banned_ips", ip, str(expiry), ttl=duration)

        if self.agent_handler:
            self._send_ban_event(ip, duration, reason)

    def _send_ban_event(self, ip: str, duration: int, reason: str) -> None:
        try:
            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="ip_banned",
                ip_address=ip,
                action_taken="banned",
                reason=reason,
                metadata={"duration": duration},
            )
            self.agent_handler.send_event(event)
        except Exception as e:
            logging.getLogger("guard_core.sync.handlers.ipban").error(
                f"Failed to send ban event to agent: {e}"
            )

    def unban_ip(self, ip: str) -> None:
        if ip in self.banned_ips:
            del self.banned_ips[ip]

        if self.redis_handler:
            self.redis_handler.delete("banned_ips", ip)

        if self.agent_handler:
            self._send_unban_event(ip)

    def _send_unban_event(self, ip: str) -> None:
        try:
            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="ip_unbanned",
                ip_address=ip,
                action_taken="unbanned",
                reason="dynamic_rule_whitelist",
                metadata={"action": "unban"},
            )
            self.agent_handler.send_event(event)
        except Exception as e:
            logging.getLogger("guard_core.sync.handlers.ipban").error(
                f"Failed to send unban event to agent: {e}"
            )

    def is_ip_banned(self, ip: str) -> bool:
        current_time = time.time()

        if ip in self.banned_ips:
            if current_time > self.banned_ips[ip]:
                del self.banned_ips[ip]
                return False
            return True

        if self.redis_handler:
            expiry = self.redis_handler.get_key("banned_ips", ip)
            if expiry:
                expiry_time = float(expiry)
                if current_time <= expiry_time:
                    self.banned_ips[ip] = expiry_time
                    return True
                self.redis_handler.delete("banned_ips", ip)

        return False

    def reset(self) -> None:
        self.banned_ips.clear()
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
