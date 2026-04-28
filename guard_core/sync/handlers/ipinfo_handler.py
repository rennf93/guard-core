import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import maxminddb
import requests
from maxminddb import Reader

from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol
from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol


class IPInfoManager:
    _instance = None
    _download_retries: int = 3
    token: str
    db_path: Path
    reader: Reader | None = None
    redis_handler: SyncRedisHandlerProtocol | None = None
    agent_handler: SyncAgentHandlerProtocol | None = None
    logger: logging.Logger
    _max_age: int

    def __new__(
        cls: type["IPInfoManager"],
        token: str,
        db_path: Path | None = None,
        max_age: int = 86400,
    ) -> "IPInfoManager":
        if not token:
            raise ValueError("IPInfo token is required!")

        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.token = token
            cls._instance.db_path = db_path or Path("data/ipinfo/country_asn.mmdb")
            cls._instance.reader = None
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None
            cls._instance.logger = logging.getLogger("guard_core.sync.handlers.ipinfo")
            cls._instance._max_age = max_age

        cls._instance.token = token
        if db_path is not None:
            cls._instance.db_path = db_path
        cls._instance._max_age = max_age
        return cls._instance

    @property
    def is_initialized(self) -> bool:
        return self.reader is not None

    def initialize_agent(self, agent_handler: SyncAgentHandlerProtocol) -> None:
        self.agent_handler = agent_handler

    def initialize(self) -> None:
        os.makedirs(self.db_path.parent, exist_ok=True)

        if self.redis_handler:
            cached_db = self.redis_handler.get_key("ipinfo", "database")
            if cached_db:
                with open(self.db_path, "wb") as f:
                    f.write(
                        cached_db
                        if isinstance(cached_db, bytes)
                        else cached_db.encode("latin-1")
                    )
                self.reader = maxminddb.open_database(str(self.db_path))
                return

        try:
            if not self.db_path.exists() or self._is_db_outdated():
                self._download_database()
        except Exception as e:
            if self.agent_handler:
                self._send_geo_event(
                    event_type="geo_lookup_failed",
                    ip_address="system",
                    action_taken="database_download_failed",
                    reason=f"Failed to download IPInfo database: {str(e)}",
                )

            if self.db_path.exists():
                self.db_path.unlink()
            self.reader = None
            return

        if self.db_path.exists():
            self.reader = maxminddb.open_database(str(self.db_path))

    def _send_geo_event(
        self,
        event_type: str,
        ip_address: str,
        action_taken: str,
        reason: str,
        **kwargs: Any,
    ) -> None:
        if not self.agent_handler:
            return

        try:
            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=event_type,
                ip_address=ip_address,
                action_taken=action_taken,
                reason=reason,
                metadata=kwargs,
            )
            self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send geo event to agent: {e}")

    def _download_database(self) -> None:
        base_url = "https://ipinfo.io/data/free/country_asn.mmdb"
        url = f"{base_url}?token={self.token}"
        retries = self._download_retries
        backoff = 1

        with requests.Session() as session:
            for attempt in range(retries):
                try:
                    response = session.get(url)
                    response.raise_for_status()
                    content = response.content
                    with open(self.db_path, "wb") as f:
                        f.write(content)

                    if self.redis_handler is not None:
                        with open(self.db_path, "rb") as f:
                            db_content = f.read().decode("latin-1")
                        self.redis_handler.set_key(
                            "ipinfo",
                            "database",
                            db_content,
                            ttl=self._max_age,
                        )
                    return
                except Exception:
                    if attempt == retries - 1:
                        raise
                    time.sleep(backoff)
                    backoff *= 2

    def _is_db_outdated(self) -> bool:
        if not self.db_path.exists():
            return True

        age = time.time() - self.db_path.stat().st_mtime
        return age > self._max_age

    def get_country(self, ip: str) -> str | None:
        if not self.reader:
            self.logger.warning(
                "Geo-IP reader uninitialized; returning None for %s", ip
            )
            return None

        try:
            result = self.reader.get(ip)
            if isinstance(result, dict) and "country" in result:
                country = result.get("country")
                return str(country) if country is not None else None
            return None
        except Exception as e:
            if self.agent_handler:
                self._send_geo_event(
                    event_type="geo_lookup_failed",
                    ip_address=ip,
                    action_taken="lookup_failed",
                    reason=f"Geographic lookup failed: {str(e)}",
                )
            return None

    def check_country_access(
        self,
        ip: str,
        blocked_countries: list[str],
        whitelist_countries: list[str] | None = None,
    ) -> tuple[bool, str | None]:
        country = self.get_country(ip)

        if not country:
            if whitelist_countries:
                return False, None
            return True, None

        if whitelist_countries and country not in whitelist_countries:
            self._send_geo_event(
                event_type="country_blocked",
                ip_address=ip,
                action_taken="request_blocked",
                reason=f"Country {country} not in allowed list",
                country=country,
                rule_type="country_whitelist",
            )
            return False, country

        if country in blocked_countries:
            self._send_geo_event(
                event_type="country_blocked",
                ip_address=ip,
                action_taken="request_blocked",
                reason=f"Country {country} is blocked",
                country=country,
                rule_type="country_blacklist",
            )
            return False, country

        return True, country

    def close(self) -> None:
        if self.reader:
            self.reader.close()

    def refresh(self) -> None:
        self.close()
        self.reader = None
        try:
            self._download_database()
        except Exception as e:
            self.logger.error(f"IPInfo refresh failed: {e}")
            return
        if self.db_path.exists():
            self.reader = maxminddb.open_database(str(self.db_path))

    def initialize_redis(self, redis_handler: SyncRedisHandlerProtocol) -> None:
        self.redis_handler = redis_handler
        self.initialize()
