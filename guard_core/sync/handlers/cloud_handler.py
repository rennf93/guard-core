import html
import ipaddress
import logging
import re
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

import requests

from guard_core.sync.handlers.cloud_ip_stores import InMemoryCloudIpStore
from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol
from guard_core.sync.protocols.cloud_ip_store_protocol import SyncCloudIpStoreProtocol
from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol

logger = logging.getLogger("guard_core.sync.handlers.cloud")


def fetch_aws_ip_ranges() -> tuple[
    set[ipaddress.IPv4Network | ipaddress.IPv6Network], dict[str, str]
]:
    try:
        with requests.Session() as session:
            response = session.get(
                "https://ip-ranges.amazonaws.com/ip-ranges.json",
                timeout=10,
            )
            response.raise_for_status()
            data = response.json()
        networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
        regions: dict[str, str] = {}
        for ip_range in data["prefixes"]:
            if ip_range["service"] != "AMAZON":
                continue
            network = ipaddress.ip_network(ip_range["ip_prefix"])
            networks.add(network)
            region = ip_range.get("region")
            if region:
                regions[str(network)] = region
        return networks, regions
    except Exception as e:
        logger.error(f"Failed to fetch AWS IP ranges: {str(e)}")
        return set(), {}


def fetch_gcp_ip_ranges() -> tuple[
    set[ipaddress.IPv4Network | ipaddress.IPv6Network], dict[str, str]
]:
    try:
        with requests.Session() as session:
            response = session.get(
                "https://www.gstatic.com/ipranges/cloud.json",
                timeout=10,
            )
            response.raise_for_status()
            data = response.json()
        networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
        regions: dict[str, str] = {}
        for ip_range in data["prefixes"]:
            prefix = ip_range.get("ipv4Prefix") or ip_range.get("ipv6Prefix")
            if not prefix:
                continue
            network = ipaddress.ip_network(prefix)
            networks.add(network)
            scope = ip_range.get("scope")
            if scope:
                regions[str(network)] = scope
        return networks, regions
    except Exception as e:
        logger.error(f"Failed to fetch GCP IP ranges: {str(e)}")
        return set(), {}


def fetch_azure_ip_ranges() -> set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/91.0.4472.124 Safari/537.36"
        }
        route = "/download/details.aspx?id=56519"
        with requests.Session() as session:
            response = session.get(
                f"https://www.microsoft.com/en-us{route}",
                headers=headers,
                timeout=10,
            )
            response.raise_for_status()
            page_text = response.text

        decoded_html = html.unescape(page_text)
        pattern = r'href=["\'](https://download\.microsoft\.com/.{1,500}?\.json)["\']'
        match = re.search(pattern, decoded_html)

        if not match:
            raise ValueError("Could not find Azure IP ranges download URL")

        download_url = match.group(1)
        with requests.Session() as session:
            response = session.get(download_url, timeout=10)
            response.raise_for_status()
            data = response.json()

        return {
            ipaddress.ip_network(ip_range)
            for ip_range in data["values"][0]["properties"]["addressPrefixes"]
        }
    except Exception as e:
        logger.error(f"Failed to fetch Azure IP ranges: {str(e)}")
        return set()


def fetch_digitalocean_ip_ranges() -> set[
    ipaddress.IPv4Network | ipaddress.IPv6Network
]:
    try:
        with requests.Session() as session:
            response = session.get(
                "https://www.digitalocean.com/geo/google.csv",
                timeout=10,
            )
            response.raise_for_status()
            body = response.text

        networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
        for raw_line in body.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            prefix = line.split(",", 1)[0].strip()
            if not prefix:
                continue
            try:
                networks.add(ipaddress.ip_network(prefix))
            except ValueError:
                continue
        return networks
    except Exception as e:
        logger.error(f"Failed to fetch DigitalOcean IP ranges: {str(e)}")
        return set()


def fetch_linode_ip_ranges() -> set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    try:
        with requests.Session() as session:
            response = session.get(
                "https://geoip.linode.com/",
                timeout=10,
            )
            response.raise_for_status()
            body = response.text

        networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
        for raw_line in body.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            prefix = line.split(",", 1)[0].strip()
            if not prefix:
                continue
            try:
                networks.add(ipaddress.ip_network(prefix))
            except ValueError:
                continue
        return networks
    except Exception as e:
        logger.error(f"Failed to fetch Linode IP ranges: {str(e)}")
        return set()


def fetch_vultr_ip_ranges() -> set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    try:
        with requests.Session() as session:
            response = session.get(
                "https://geofeed.constant.com/?json",
                timeout=10,
            )
            response.raise_for_status()
            data = response.json()

        networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
        for entry in data.get("subnets", []):
            prefix = entry.get("ip_prefix")
            if not prefix:
                continue
            try:
                networks.add(ipaddress.ip_network(prefix))
            except ValueError:
                continue
        return networks
    except Exception as e:
        logger.error(f"Failed to fetch Vultr IP ranges: {str(e)}")
        return set()


_ALL_PROVIDERS = set({"AWS", "GCP", "Azure", "DigitalOcean", "Linode", "Vultr"})


def _parse_cloud_selectors(
    selectors: set[str],
) -> tuple[set[str], dict[str, set[str]]]:
    blocked: set[str] = set()
    carveouts: dict[str, set[str]] = {}
    for selector in selectors:
        provider, marker, region = selector.partition(":!")
        blocked.add(provider)
        if marker and region:
            carveouts.setdefault(provider, set()).add(region)
    return blocked, carveouts


def _fetch_provider_ranges(
    provider: str,
) -> tuple[set[ipaddress.IPv4Network | ipaddress.IPv6Network], dict[str, str]]:
    fetchers = {
        "AWS": fetch_aws_ip_ranges,
        "GCP": fetch_gcp_ip_ranges,
        "Azure": fetch_azure_ip_ranges,
        "DigitalOcean": fetch_digitalocean_ip_ranges,
        "Linode": fetch_linode_ip_ranges,
        "Vultr": fetch_vultr_ip_ranges,
    }
    result: Any = fetchers[provider]()
    if isinstance(result, tuple):
        return result
    return result, {}


def _encode_cached(
    ranges: set[ipaddress.IPv4Network | ipaddress.IPv6Network],
    regions: dict[str, str],
) -> set[str]:
    encoded: set[str] = set()
    for network in ranges:
        key = str(network)
        region = regions.get(key)
        encoded.add(f"{key}|{region}" if region else key)
    return encoded


def _decode_cached(
    entries: set[str],
) -> tuple[set[ipaddress.IPv4Network | ipaddress.IPv6Network], dict[str, str]]:
    networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
    regions: dict[str, str] = {}
    for entry in entries:
        prefix, separator, region = entry.partition("|")
        network = ipaddress.ip_network(prefix)
        networks.add(network)
        if separator and region:
            regions[str(network)] = region
    return networks, regions


class CloudManager:
    _instance = None
    ip_ranges: dict[str, set[ipaddress.IPv4Network | ipaddress.IPv6Network]]
    network_regions: dict[str, dict[str, str]]
    redis_handler: SyncRedisHandlerProtocol | None = None
    agent_handler: SyncAgentHandlerProtocol | None = None
    logger: logging.Logger
    last_updated: dict[str, datetime | None]
    _store: SyncCloudIpStoreProtocol | None
    _refresh_task: threading.Thread | None
    _refresh_in_flight: bool
    _refresh_lock: threading.Lock

    def __new__(cls: type["CloudManager"]) -> "CloudManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.ip_ranges = {
                "AWS": set(),
                "GCP": set(),
                "Azure": set(),
                "DigitalOcean": set(),
                "Linode": set(),
                "Vultr": set(),
            }
            cls._instance.network_regions = {
                provider: {} for provider in _ALL_PROVIDERS
            }
            cls._instance.last_updated = {provider: None for provider in _ALL_PROVIDERS}
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None
            cls._instance.logger = logging.getLogger("guard_core.sync.handlers.cloud")
            cls._instance._store = InMemoryCloudIpStore()
            cls._instance._refresh_task = None
            cls._instance._refresh_in_flight = False
            cls._instance._refresh_lock = threading.Lock()
        return cls._instance

    def set_store(self, store: SyncCloudIpStoreProtocol) -> None:
        self._store = store

    def schedule_refresh(
        self,
        providers: set[str] = _ALL_PROVIDERS,
        ttl: int = 3600,
        refresh: Callable[[], None] | None = None,
    ) -> bool:
        """Refresh cloud IP ranges in the background without blocking the caller.

        Cloud-provider range fetches are multi-second network calls; running them
        inline on the request path blocks request handling for every caller. This
        fires the refresh as a single-flight background task instead: while one is in
        flight, further calls are no-ops. The gate is lock-guarded so concurrent
        callers (multi-threaded sync deployments) can't start duplicate refreshes.
        Passing ``refresh`` runs that callable as the background refresh instead of
        this manager's own ``refresh_async`` — middleware callers use it to keep
        adapter overrides of ``refresh_cloud_ip_ranges`` on the periodic path.
        Returns True if a task was started.
        """

        def _run_refresh() -> None:
            try:
                if refresh is None:
                    self.refresh_async(providers, ttl=ttl)
                else:
                    refresh()
            except Exception:
                self.logger.exception("Background cloud IP refresh failed")
            finally:
                self._refresh_in_flight = False

        with self._refresh_lock:
            if self._refresh_in_flight:
                return False
            self._refresh_in_flight = True
            try:
                self._refresh_task = threading.Thread(target=_run_refresh, daemon=True)

                self._refresh_task.start()
            except RuntimeError:
                self.logger.exception("Could not schedule cloud IP refresh")
                self._refresh_in_flight = False
                return False
            return True

    def _log_range_changes(
        self,
        provider: str,
        old_ranges: set[ipaddress.IPv4Network | ipaddress.IPv6Network],
        new_ranges: set[ipaddress.IPv4Network | ipaddress.IPv6Network],
    ) -> None:
        if old_ranges == new_ranges:
            return
        added = new_ranges - old_ranges
        removed = old_ranges - new_ranges
        self.logger.info(
            f"Cloud IP range update for {provider}: "
            f"+{len(added)} added, -{len(removed)} removed"
        )

    def _refresh_providers(self, providers: set[str] = _ALL_PROVIDERS) -> None:
        for provider in providers:
            try:
                ranges, regions = _fetch_provider_ranges(provider)
                if ranges:
                    old_ranges = self.ip_ranges.get(provider, set())
                    self._log_range_changes(provider, old_ranges, ranges)
                    self.ip_ranges[provider] = ranges
                    self.network_regions[provider] = regions
                    self.last_updated[provider] = datetime.now(timezone.utc)
            except Exception as e:
                self.logger.error(f"Failed to fetch {provider} IP ranges: {str(e)}")
                self.ip_ranges[provider] = set()
                self.network_regions[provider] = {}

    def initialize_redis(
        self,
        redis_handler: SyncRedisHandlerProtocol,
        providers: set[str] = _ALL_PROVIDERS,
        ttl: int = 3600,
    ) -> None:
        self.redis_handler = redis_handler
        if isinstance(self._store, InMemoryCloudIpStore):
            from guard_core.sync.handlers.cloud_ip_stores import RedisCloudIpStore

            self._store = RedisCloudIpStore(redis_handler)
        self.refresh_async(providers, ttl=ttl)

    def initialize_agent(self, agent_handler: SyncAgentHandlerProtocol) -> None:
        self.agent_handler = agent_handler

    def refresh(self, providers: set[str] = _ALL_PROVIDERS) -> None:
        if self.redis_handler is not None:
            raise RuntimeError("Use refresh_async() when Redis is enabled")
        self._refresh_providers(providers)

    def refresh_async(
        self, providers: set[str] = _ALL_PROVIDERS, ttl: int = 3600
    ) -> None:
        if self._store is None:
            self._refresh_providers_via_redis_handler(providers, ttl=ttl)
            return

        for provider in providers:
            try:
                cached = self._store.get(provider)
                if cached is not None:
                    nets, regions = _decode_cached(cached)
                    self.ip_ranges[provider] = nets
                    self.network_regions[provider] = regions
                    continue

                ranges, regions = _fetch_provider_ranges(provider)
                if ranges:
                    old_ranges = self.ip_ranges.get(provider, set())
                    self._log_range_changes(provider, old_ranges, ranges)
                    self.ip_ranges[provider] = ranges
                    self.network_regions[provider] = regions
                    self.last_updated[provider] = datetime.now(timezone.utc)
                    self._store.set(
                        provider,
                        _encode_cached(ranges, regions),
                        ttl=ttl,
                    )
            except Exception as e:
                self.logger.error(f"Failed to refresh {provider} IP ranges: {str(e)}")
                if provider not in self.ip_ranges:
                    self.ip_ranges[provider] = set()

    def _refresh_providers_via_redis_handler(
        self, providers: set[str], ttl: int = 3600
    ) -> None:
        if self.redis_handler is None:
            self._refresh_providers(providers)
            return

        for provider in providers:
            try:
                cached = self.redis_handler.get_key("cloud_ranges_v2", provider)
                if cached:
                    nets, regions = _decode_cached(set(cached.split(",")))
                    self.ip_ranges[provider] = nets
                    self.network_regions[provider] = regions
                    continue

                ranges, regions = _fetch_provider_ranges(provider)
                if ranges:
                    old_ranges = self.ip_ranges.get(provider, set())
                    self._log_range_changes(provider, old_ranges, ranges)
                    self.ip_ranges[provider] = ranges
                    self.network_regions[provider] = regions
                    self.last_updated[provider] = datetime.now(timezone.utc)
                    self.redis_handler.set_key(
                        "cloud_ranges_v2",
                        provider,
                        ",".join(sorted(_encode_cached(ranges, regions))),
                        ttl=ttl,
                    )
            except Exception as e:
                self.logger.error(f"Failed to refresh {provider} IP ranges: {str(e)}")
                if provider not in self.ip_ranges:
                    self.ip_ranges[provider] = set()

    def is_cloud_ip(self, ip: str, providers: set[str] = _ALL_PROVIDERS) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            blocked, carveouts = _parse_cloud_selectors(providers)
            for provider in blocked:
                if provider not in self.ip_ranges:
                    continue
                allowed_regions = carveouts.get(provider)
                provider_regions = self.network_regions.get(provider, {})
                for network in self.ip_ranges[provider]:
                    if ip_obj in network:
                        if allowed_regions and (
                            provider_regions.get(str(network)) in allowed_regions
                        ):
                            continue
                        return True
            return False
        except ValueError:
            self.logger.error(f"Invalid IP address: {ip}")
            return False

    def get_cloud_provider_details(
        self, ip: str, providers: set[str] = _ALL_PROVIDERS
    ) -> tuple[str, str] | None:
        try:
            ip_obj = ipaddress.ip_address(ip)
            for provider in providers:
                if provider in self.ip_ranges:
                    for network in self.ip_ranges[provider]:
                        if ip_obj in network:
                            return (provider, str(network))
            return None
        except ValueError:
            self.logger.error(f"Invalid IP address: {ip}")
            return None

    def send_cloud_detection_event(
        self,
        ip: str,
        provider: str,
        network: str,
        action_taken: str = "request_blocked",
    ) -> None:
        from guard_core.sync.core.events.event_types import EVENT_CLOUD_BLOCKED

        if not self.agent_handler:
            return

        self._send_cloud_event(
            event_type=EVENT_CLOUD_BLOCKED,
            ip_address=ip,
            action_taken=action_taken,
            reason=f"IP belongs to blocked cloud provider: {provider}",
            cloud_provider=provider,
            network=network,
        )

    def _send_cloud_event(
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
            self.logger.error(f"Failed to send cloud event to agent: {e}")


cloud_handler = CloudManager()
