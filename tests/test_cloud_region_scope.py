import ipaddress
from collections.abc import Generator

import pytest

from guard_core.handlers.cloud_handler import (
    CloudManager,
    _decode_cached,
    _encode_cached,
    _parse_cloud_selectors,
)
from guard_core.models import SecurityConfig


def test_security_config_keeps_region_selector() -> None:
    config = SecurityConfig(block_cloud_providers={"GCP:!us-central1"})
    assert config.block_cloud_providers == {"GCP:!us-central1"}


def test_security_config_keeps_bare_provider() -> None:
    config = SecurityConfig(block_cloud_providers={"GCP"})
    assert config.block_cloud_providers == {"GCP"}


def test_security_config_drops_unknown_provider_selector() -> None:
    config = SecurityConfig(block_cloud_providers={"Bogus:!x", "GCP"})
    assert config.block_cloud_providers == {"GCP"}


def test_parse_selectors_bare_provider() -> None:
    blocked, carveouts = _parse_cloud_selectors({"GCP"})
    assert blocked == {"GCP"}
    assert carveouts == {}


def test_parse_selectors_carveout() -> None:
    blocked, carveouts = _parse_cloud_selectors({"GCP:!us-central1"})
    assert blocked == {"GCP"}
    assert carveouts == {"GCP": {"us-central1"}}


def test_parse_selectors_mixed_providers_and_carveouts() -> None:
    blocked, carveouts = _parse_cloud_selectors(
        {"GCP", "GCP:!us-central1", "AWS:!us-east-1"}
    )
    assert blocked == {"GCP", "AWS"}
    assert carveouts == {"GCP": {"us-central1"}, "AWS": {"us-east-1"}}


def test_parse_selectors_carveout_implies_provider_block() -> None:
    blocked, carveouts = _parse_cloud_selectors({"AWS:!us-east-1"})
    assert blocked == {"AWS"}
    assert carveouts == {"AWS": {"us-east-1"}}


@pytest.fixture
def gcp_regions() -> Generator[tuple[CloudManager, str, str], None, None]:
    manager = CloudManager()
    saved_ranges = dict(manager.ip_ranges)
    saved_regions = dict(manager.network_regions)
    net_central = ipaddress.ip_network("34.100.0.0/24")
    net_europe = ipaddress.ip_network("35.200.0.0/24")
    manager.ip_ranges["GCP"] = {net_central, net_europe}
    manager.network_regions["GCP"] = {
        str(net_central): "us-central1",
        str(net_europe): "europe-west1",
    }
    yield manager, "34.100.0.5", "35.200.0.5"
    manager.ip_ranges = saved_ranges
    manager.network_regions = saved_regions


def test_block_whole_provider_unchanged(
    gcp_regions: tuple[CloudManager, str, str],
) -> None:
    manager, central_ip, europe_ip = gcp_regions
    assert manager.is_cloud_ip(central_ip, {"GCP"}) is True
    assert manager.is_cloud_ip(europe_ip, {"GCP"}) is True


def test_carveout_allows_excepted_region(
    gcp_regions: tuple[CloudManager, str, str],
) -> None:
    manager, central_ip, europe_ip = gcp_regions
    assert manager.is_cloud_ip(central_ip, {"GCP:!us-central1"}) is False
    assert manager.is_cloud_ip(europe_ip, {"GCP:!us-central1"}) is True


def test_carveout_other_region_still_blocked(
    gcp_regions: tuple[CloudManager, str, str],
) -> None:
    manager, central_ip, _ = gcp_regions
    assert manager.is_cloud_ip(central_ip, {"GCP:!europe-west1"}) is True


def test_non_cloud_ip_not_blocked(
    gcp_regions: tuple[CloudManager, str, str],
) -> None:
    manager, _, _ = gcp_regions
    assert manager.is_cloud_ip("8.8.8.8", {"GCP"}) is False
    assert manager.is_cloud_ip("8.8.8.8", {"GCP:!us-central1"}) is False


def test_cache_encode_decode_roundtrip_preserves_region() -> None:
    net_a = ipaddress.ip_network("34.100.0.0/24")
    net_b = ipaddress.ip_network("8.8.8.0/24")
    ranges = {net_a, net_b}
    regions = {str(net_a): "us-central1"}

    encoded = _encode_cached(ranges, regions)
    nets, decoded_regions = _decode_cached(encoded)

    assert nets == ranges
    assert decoded_regions == {str(net_a): "us-central1"}


def test_decode_tolerates_legacy_unscoped_entries() -> None:
    net = ipaddress.ip_network("34.100.0.0/24")
    nets, regions = _decode_cached({str(net)})
    assert nets == {net}
    assert regions == {}


async def test_refresh_populates_network_regions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    net = ipaddress.ip_network("34.100.0.0/24")

    async def fake_gcp() -> tuple[set[ipaddress.IPv4Network], dict[str, str]]:
        return {net}, {str(net): "us-central1"}

    monkeypatch.setattr(
        "guard_core.handlers.cloud_handler.fetch_gcp_ip_ranges", fake_gcp
    )
    manager = CloudManager()
    saved_ranges = dict(manager.ip_ranges)
    saved_regions = dict(manager.network_regions)

    await manager._refresh_providers({"GCP"})

    assert manager.network_regions["GCP"] == {str(net): "us-central1"}
    assert manager.is_cloud_ip("34.100.0.5", {"GCP:!us-central1"}) is False

    manager.ip_ranges = saved_ranges
    manager.network_regions = saved_regions
