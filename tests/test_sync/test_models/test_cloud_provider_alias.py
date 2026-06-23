from typing import get_args

import pytest

from guard_core.models import VALID_CLOUD_PROVIDERS, CloudProvider


def test_cloud_provider_literal_members() -> None:
    assert get_args(CloudProvider) == ("AWS", "GCP", "Azure")


def test_valid_cloud_providers_is_frozenset_of_literal_members() -> None:
    assert isinstance(VALID_CLOUD_PROVIDERS, frozenset)
    assert VALID_CLOUD_PROVIDERS == frozenset({"AWS", "GCP", "Azure"})


def test_valid_cloud_providers_immutable() -> None:
    with pytest.raises(AttributeError):
        VALID_CLOUD_PROVIDERS.add("DigitalOcean")  # type: ignore[attr-defined]
