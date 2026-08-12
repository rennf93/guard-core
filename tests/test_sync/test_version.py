import importlib
import importlib.metadata

import pytest

import guard_core


def test_dunder_version_matches_installed_package_metadata() -> None:
    assert guard_core.__version__ == importlib.metadata.version("guard-core")


def test_dunder_version_falls_back_to_unknown_when_package_metadata_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _raise_not_found(name: str) -> str:
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", _raise_not_found)
    importlib.reload(guard_core)

    try:
        assert guard_core.__version__ == "unknown"
    finally:
        monkeypatch.undo()
        importlib.reload(guard_core)
