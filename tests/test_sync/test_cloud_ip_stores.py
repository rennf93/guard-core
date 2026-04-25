import ipaddress
import json
from collections.abc import Generator
from unittest.mock import MagicMock

import pytest

from guard_core.sync.handlers.cloud_handler import CloudManager
from guard_core.sync.handlers.cloud_ip_stores import (
    InMemoryCloudIpStore,
    RedisCloudIpStore,
)
from guard_core.sync.protocols.cloud_ip_store_protocol import SyncCloudIpStoreProtocol


def test_in_memory_store_implements_protocol() -> None:
    assert isinstance(InMemoryCloudIpStore(), SyncCloudIpStoreProtocol)


def test_in_memory_store_round_trip() -> None:
    store = InMemoryCloudIpStore()
    assert store.get("AWS") is None
    store.set("AWS", {"10.0.0.0/8", "192.168.0.0/16"})
    assert store.get("AWS") == {"10.0.0.0/8", "192.168.0.0/16"}


def test_in_memory_store_set_is_isolated_from_source_mutation() -> None:
    store = InMemoryCloudIpStore()
    source = {"10.0.0.0/8"}
    store.set("AWS", source)
    source.add("192.168.0.0/16")
    assert store.get("AWS") == {"10.0.0.0/8"}


def test_in_memory_store_clear() -> None:
    store = InMemoryCloudIpStore()
    store.set("AWS", {"10.0.0.0/8"})
    store.clear()
    assert store.get("AWS") is None


def test_redis_store_implements_protocol() -> None:
    assert isinstance(RedisCloudIpStore(MagicMock()), SyncCloudIpStoreProtocol)


def test_redis_store_set_writes_json_with_ttl() -> None:
    redis_handler = MagicMock()
    redis_handler.set_key = MagicMock()
    store = RedisCloudIpStore(redis_handler, key_prefix="guard:cloud_ip")
    store.set("AWS", {"10.0.0.0/8", "192.168.0.0/16"}, ttl=120)
    redis_handler.set_key.assert_called_once()
    call = redis_handler.set_key.call_args
    assert call.args[0] == "guard:cloud_ip"
    assert call.args[1] == "AWS"
    payload = json.loads(call.args[2])
    assert set(payload) == {"10.0.0.0/8", "192.168.0.0/16"}
    assert call.kwargs["ttl"] == 120


def test_redis_store_get_returns_none_on_miss() -> None:
    redis_handler = MagicMock()
    redis_handler.get_key = MagicMock(return_value=None)
    store = RedisCloudIpStore(redis_handler)
    assert store.get("AWS") is None


def test_redis_store_get_parses_json() -> None:
    redis_handler = MagicMock()
    redis_handler.get_key = MagicMock(return_value=json.dumps(["10.0.0.0/8"]))
    store = RedisCloudIpStore(redis_handler)
    assert store.get("AWS") == {"10.0.0.0/8"}


def test_redis_store_get_returns_none_on_invalid_json() -> None:
    redis_handler = MagicMock()
    redis_handler.get_key = MagicMock(return_value="not-json{")
    store = RedisCloudIpStore(redis_handler)
    assert store.get("AWS") is None


def test_redis_store_get_returns_none_when_payload_not_list() -> None:
    redis_handler = MagicMock()
    redis_handler.get_key = MagicMock(return_value=json.dumps({"oops": True}))
    store = RedisCloudIpStore(redis_handler)
    assert store.get("AWS") is None


def test_redis_store_clear_deletes_matching_keys() -> None:
    redis_handler = MagicMock()
    redis_handler.keys = MagicMock(
        return_value=["guard:cloud_ip:AWS", "guard:cloud_ip:GCP"]
    )
    redis_handler.delete = MagicMock()
    store = RedisCloudIpStore(redis_handler, key_prefix="guard:cloud_ip")
    store.clear()
    assert redis_handler.delete.call_count == 2


def test_redis_store_clear_returns_when_no_keys() -> None:
    redis_handler = MagicMock()
    redis_handler.keys = MagicMock(return_value=None)
    redis_handler.delete = MagicMock()
    store = RedisCloudIpStore(redis_handler)
    store.clear()
    redis_handler.delete.assert_not_called()


def test_redis_store_clear_skips_keys_without_provider_suffix() -> None:
    redis_handler = MagicMock()
    redis_handler.keys = MagicMock(return_value=["guard:cloud_ip:"])
    redis_handler.delete = MagicMock()
    store = RedisCloudIpStore(redis_handler, key_prefix="guard:cloud_ip")
    store.clear()
    redis_handler.delete.assert_not_called()


@pytest.fixture(autouse=True)
def _reset_cloud_singleton() -> Generator[None, None, None]:
    from guard_core.sync.handlers.cloud_handler import cloud_handler as _cloud
    from guard_core.sync.handlers.cloud_ip_stores import InMemoryCloudIpStore

    _cloud.ip_ranges = {"AWS": set(), "GCP": set(), "Azure": set()}
    _cloud.last_updated = {"AWS": None, "GCP": None, "Azure": None}
    _cloud.redis_handler = None
    _cloud.agent_handler = None
    _cloud._store = InMemoryCloudIpStore()
    yield
    _cloud.ip_ranges = {"AWS": set(), "GCP": set(), "Azure": set()}
    _cloud.last_updated = {"AWS": None, "GCP": None, "Azure": None}
    _cloud.redis_handler = None
    _cloud.agent_handler = None
    _cloud._store = InMemoryCloudIpStore()


def test_cloud_manager_reads_from_store_on_refresh() -> None:
    store = InMemoryCloudIpStore()
    store.set("AWS", {"10.0.0.0/8"})
    mgr = CloudManager()
    mgr.set_store(store)
    mgr.refresh_async({"AWS"})
    assert ipaddress.ip_network("10.0.0.0/8") in mgr.ip_ranges["AWS"]


def test_cloud_manager_writes_to_store_after_api_fetch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = InMemoryCloudIpStore()
    mgr = CloudManager()
    mgr.set_store(store)

    def fake_aws() -> set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return {ipaddress.ip_network("172.16.0.0/12")}

    monkeypatch.setattr(
        "guard_core.sync.handlers.cloud_handler.fetch_aws_ip_ranges", fake_aws
    )
    mgr.refresh_async({"AWS"})
    assert store.get("AWS") == {"172.16.0.0/12"}
    assert ipaddress.ip_network("172.16.0.0/12") in mgr.ip_ranges["AWS"]


def test_cloud_manager_without_explicit_store_uses_default_in_memory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mgr = CloudManager()
    assert mgr._store is not None
    captured: list[str] = []

    def fake_gcp() -> set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        captured.append("fetched")
        return {ipaddress.ip_network("10.0.0.0/8")}

    monkeypatch.setattr(
        "guard_core.sync.handlers.cloud_handler.fetch_gcp_ip_ranges", fake_gcp
    )
    mgr.refresh_async({"GCP"})
    assert captured == ["fetched"]
    captured.clear()
    mgr.refresh_async({"GCP"})
    assert captured == []


def test_cloud_manager_with_store_none_uses_legacy_redis_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mgr = CloudManager()
    mgr._store = None
    redis_handler = MagicMock()
    redis_handler.get_key = MagicMock(return_value="10.0.0.0/8")
    redis_handler.set_key = MagicMock()
    mgr.redis_handler = redis_handler
    mgr.refresh_async({"AWS"})
    assert ipaddress.ip_network("10.0.0.0/8") in mgr.ip_ranges["AWS"]


def test_cloud_manager_with_store_none_and_no_redis_falls_back_to_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mgr = CloudManager()
    mgr._store = None
    mgr.redis_handler = None
    captured: list[str] = []

    def fake_aws() -> set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        captured.append("fetched")
        return {ipaddress.ip_network("203.0.113.0/24")}

    monkeypatch.setattr(
        "guard_core.sync.handlers.cloud_handler.fetch_aws_ip_ranges", fake_aws
    )
    mgr.refresh_async({"AWS"})
    assert captured == ["fetched"]
    assert ipaddress.ip_network("203.0.113.0/24") in mgr.ip_ranges["AWS"]


def test_cloud_manager_store_path_handles_fetch_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = InMemoryCloudIpStore()
    mgr = CloudManager()
    mgr.set_store(store)
    mgr.ip_ranges.pop("Azure", None)

    def boom() -> set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        raise RuntimeError("API down")

    monkeypatch.setattr(
        "guard_core.sync.handlers.cloud_handler.fetch_azure_ip_ranges", boom
    )
    mgr.refresh_async({"Azure"})
    assert mgr.ip_ranges["Azure"] == set()


def test_cloud_manager_initialize_redis_upgrades_default_store_to_redis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mgr = CloudManager()
    assert isinstance(mgr._store, InMemoryCloudIpStore)
    redis_handler = MagicMock()
    redis_handler.get_key = MagicMock(return_value=None)
    redis_handler.set_key = MagicMock()

    def _no_op_refresh(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(mgr, "refresh_async", _no_op_refresh)
    mgr.initialize_redis(redis_handler, {"AWS"})
    assert isinstance(mgr._store, RedisCloudIpStore)


def test_cloud_manager_initialize_redis_keeps_user_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mgr = CloudManager()

    class _CustomStore:
        def get(self, provider: str) -> set[str] | None:
            return None

        def set(self, provider: str, ranges: set[str], ttl: int | None = None) -> None:
            return None

        def clear(self) -> None:
            return None

    user_store = _CustomStore()
    mgr.set_store(user_store)
    redis_handler = MagicMock()

    def _no_op_refresh(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(mgr, "refresh_async", _no_op_refresh)
    mgr.initialize_redis(redis_handler, {"AWS"})
    assert mgr._store is user_store


def test_cloud_manager_legacy_redis_handler_path_handles_fetch_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mgr = CloudManager()
    mgr._store = None
    redis_handler = MagicMock()
    redis_handler.get_key = MagicMock(return_value=None)
    redis_handler.set_key = MagicMock()
    mgr.redis_handler = redis_handler
    mgr.ip_ranges.pop("Azure", None)

    def boom() -> set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        raise RuntimeError("legacy fail")

    monkeypatch.setattr(
        "guard_core.sync.handlers.cloud_handler.fetch_azure_ip_ranges", boom
    )
    mgr.refresh_async({"Azure"})
    assert mgr.ip_ranges["Azure"] == set()


def test_cloud_manager_legacy_redis_handler_writes_back_after_fetch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mgr = CloudManager()
    mgr._store = None
    redis_handler = MagicMock()
    redis_handler.get_key = MagicMock(return_value=None)
    redis_handler.set_key = MagicMock()
    mgr.redis_handler = redis_handler

    def fake_aws() -> set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return {ipaddress.ip_network("198.51.100.0/24")}

    monkeypatch.setattr(
        "guard_core.sync.handlers.cloud_handler.fetch_aws_ip_ranges", fake_aws
    )
    mgr.refresh_async({"AWS"}, ttl=900)
    assert ipaddress.ip_network("198.51.100.0/24") in mgr.ip_ranges["AWS"]
    redis_handler.set_key.assert_called_once()
    call = redis_handler.set_key.call_args
    assert call.args[0] == "cloud_ranges"
    assert call.args[1] == "AWS"
    assert call.kwargs["ttl"] == 900


def test_cloud_manager_legacy_redis_path_preserves_existing_ranges_on_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mgr = CloudManager()
    mgr._store = None
    redis_handler = MagicMock()
    redis_handler.get_key = MagicMock(return_value=None)
    redis_handler.set_key = MagicMock()
    mgr.redis_handler = redis_handler
    mgr.ip_ranges["AWS"] = {ipaddress.ip_network("10.0.0.0/8")}

    def boom() -> set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        raise RuntimeError("legacy fail")

    monkeypatch.setattr(
        "guard_core.sync.handlers.cloud_handler.fetch_aws_ip_ranges", boom
    )
    mgr.refresh_async({"AWS"})
    assert mgr.ip_ranges["AWS"] == {ipaddress.ip_network("10.0.0.0/8")}


def test_cloud_manager_legacy_redis_path_skips_write_when_fetch_returns_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mgr = CloudManager()
    mgr._store = None
    redis_handler = MagicMock()
    redis_handler.get_key = MagicMock(return_value=None)
    redis_handler.set_key = MagicMock()
    mgr.redis_handler = redis_handler

    def empty() -> set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return set()

    monkeypatch.setattr(
        "guard_core.sync.handlers.cloud_handler.fetch_aws_ip_ranges", empty
    )
    mgr.refresh_async({"AWS"})
    redis_handler.set_key.assert_not_called()
