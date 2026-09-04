from __future__ import annotations

import subprocess
import sys

import pytest


@pytest.mark.parametrize(
    "module_name",
    ["guard_core", "guard_core.sync.core.events.enricher"],
)
def test_fresh_interpreter_import_does_not_cycle(module_name: str) -> None:
    result = subprocess.run(
        [sys.executable, "-c", f"import {module_name}"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
