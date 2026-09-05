from __future__ import annotations

import importlib
import os
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "live_smoke: end-to-end scenarios against the live Docker stack "
        "(requires LIVE_SMOKE=1 and Docker)",
    )
    importlib.import_module("tests.live_smoke.scenarios")


def pytest_ignore_collect(collection_path: Path, config: pytest.Config) -> bool | None:
    if os.environ.get("LIVE_SMOKE") == "1":
        return None
    try:
        collection_path.relative_to(_HERE)
    except ValueError:
        return None
    return True


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    ours: list[pytest.Item] = []
    others: list[pytest.Item] = []
    for item in items:
        try:
            item.path.relative_to(_HERE)
        except ValueError:
            others.append(item)
            continue
        item.add_marker(pytest.mark.live_smoke)
        ours.append(item)

    ours.sort(key=lambda item: item.path.name == "test_completeness.py")
    items[:] = others + ours
