import ipaddress
from collections.abc import Collection

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


def _bare_provider_names(providers: Collection[str]) -> set[str]:
    return {provider.partition(":!")[0] for provider in providers}


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
