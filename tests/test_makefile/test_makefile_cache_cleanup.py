import shutil
import subprocess
from pathlib import Path

import pytest


def _find_repo_root(start: Path) -> Path:
    for candidate in (start, *start.parents):
        if (candidate / "Makefile").exists() and (
            candidate / "pyproject.toml"
        ).exists():
            return candidate
    raise RuntimeError(f"could not locate repo root above {start}")


REPO_ROOT = _find_repo_root(Path(__file__).resolve())
MAKEFILE = REPO_ROOT / "Makefile"


def _build_cache_tree(work_dir: Path) -> None:
    guard_core_dir = work_dir / "src" / "guard_core"
    (guard_core_dir / "__pycache__").mkdir(parents=True)
    (guard_core_dir / "__pycache__" / "mod.cpython-310.pyc").touch()
    (guard_core_dir / "compiled.pyc").touch()
    (guard_core_dir / "compiled.pyo").touch()

    (work_dir / ".pytest_cache" / "v" / "cache").mkdir(parents=True)
    (work_dir / ".pytest_cache" / "v" / "cache" / "lastfailed").touch()

    (work_dir / ".ruff_cache").mkdir()
    (work_dir / ".ruff_cache" / "data").touch()

    (work_dir / ".mypy_cache").mkdir()
    (work_dir / ".mypy_cache" / "data.json").touch()

    (work_dir / "my project" / "__pycache__").mkdir(parents=True)
    (work_dir / "my project" / "__pycache__" / "keepme.txt").touch()
    (work_dir / "my project" / "keep_this_file.txt").touch()

    (work_dir / "my" / "unrelated_valuable_data").mkdir(parents=True)
    (work_dir / "my" / "unrelated_valuable_data" / "do_not_delete.txt").touch()


def test_cache_cleanup_preserves_unrelated_paths_with_spaces(tmp_path: Path) -> None:
    if shutil.which("make") is None:
        pytest.skip("make not available on this platform")

    work_dir = tmp_path / "work"
    _build_cache_tree(work_dir)

    result = subprocess.run(
        ["make", "-f", str(MAKEFILE), "clean"],
        cwd=work_dir,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    assert not (work_dir / ".pytest_cache").exists()
    assert not (work_dir / ".ruff_cache").exists()
    assert not (work_dir / ".mypy_cache").exists()
    assert not (work_dir / "src" / "guard_core" / "__pycache__").exists()
    assert not (work_dir / "src" / "guard_core" / "compiled.pyc").exists()
    assert not (work_dir / "src" / "guard_core" / "compiled.pyo").exists()
    assert not (work_dir / "my project" / "__pycache__").exists()

    assert (work_dir / "my project" / "keep_this_file.txt").exists()
    assert (work_dir / "my" / "unrelated_valuable_data" / "do_not_delete.txt").exists()
