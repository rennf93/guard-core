import warnings
from pathlib import Path

import pytest

from guard_core.models import SecurityConfig


def test_ipinfo_token_emits_deprecation_warning() -> None:
    with pytest.warns(DeprecationWarning, match="ipinfo_token is deprecated"):
        SecurityConfig(ipinfo_token="x")


def test_ipinfo_db_path_emits_deprecation_warning() -> None:
    with pytest.warns(DeprecationWarning, match="ipinfo_db_path is deprecated"):
        SecurityConfig(ipinfo_db_path=Path("data/custom.mmdb"))


def test_both_deprecated_fields_emit_two_warnings() -> None:
    with pytest.warns(DeprecationWarning) as records:
        SecurityConfig(ipinfo_token="x", ipinfo_db_path=Path("data/custom.mmdb"))
    messages = [str(record.message) for record in records]
    assert any("ipinfo_token is deprecated" in message for message in messages)
    assert any("ipinfo_db_path is deprecated" in message for message in messages)


def test_no_deprecation_warning_when_ipinfo_unset() -> None:
    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        SecurityConfig(whitelist=["10.0.0.0/8"])
    ipinfo_deprecations = [
        record
        for record in records
        if "ipinfo" in str(record.message) and "deprecated" in str(record.message)
    ]
    assert ipinfo_deprecations == []
