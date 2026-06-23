from guard_core.models import VALID_CLOUD_PROVIDERS, SecurityConfig


def test_block_cloud_providers_none_becomes_empty_set() -> None:
    config = SecurityConfig(block_cloud_providers=None)
    assert config.block_cloud_providers == set()


def test_block_cloud_providers_filters_invalid_entries() -> None:
    config = SecurityConfig(block_cloud_providers={"AWS", "Bogus", "GCP"})
    assert config.block_cloud_providers == {"AWS", "GCP"}


def test_block_cloud_providers_accepts_full_valid_set() -> None:
    config = SecurityConfig(block_cloud_providers={"AWS", "GCP", "Azure"})
    assert config.block_cloud_providers == {"AWS", "GCP", "Azure"}


def test_block_cloud_providers_validator_uses_module_constant() -> None:
    assert VALID_CLOUD_PROVIDERS == frozenset({"AWS", "GCP", "Azure"})


def test_block_cloud_providers_invalid_only_returns_empty_set() -> None:
    config = SecurityConfig(block_cloud_providers={"Bogus1", "Bogus2"})
    assert config.block_cloud_providers == set()
