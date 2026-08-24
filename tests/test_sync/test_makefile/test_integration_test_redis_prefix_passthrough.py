import os
import shutil
import subprocess
import sys
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

FAKE_UV_TEMPLATE = """#!/bin/sh
shift
shift
exec {python} -c 'import os; print(repr(os.environ.get("REDIS_PREFIX")))'
"""


def _make_fake_uv(bin_dir: Path) -> None:
    fake_uv = bin_dir / "uv"
    fake_uv.write_text(FAKE_UV_TEMPLATE.format(python=sys.executable))
    fake_uv.chmod(0o755)


def _run_integration_test(
    tmp_path: Path, redis_prefix: str | None, shell: str | None
) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _make_fake_uv(bin_dir)
    work_dir = tmp_path / "work"
    work_dir.mkdir()

    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
    if redis_prefix is None:
        env.pop("REDIS_PREFIX", None)
    else:
        env["REDIS_PREFIX"] = redis_prefix

    args = ["make", "-f", str(MAKEFILE)]
    if shell is not None:
        args.append(f"SHELL={shell}")
    args.append("integration-test")

    return subprocess.run(
        args,
        cwd=work_dir,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _require_make_and_sh() -> None:
    if shutil.which("make") is None or not Path("/bin/sh").exists():
        pytest.skip("make or /bin/sh not available on this platform")


@pytest.mark.parametrize(
    "redis_prefix",
    [None, "myprefix", "my prefix", "myprefix:"],
    ids=["unset", "plain", "space", "trailing_colon"],
)
def test_integration_test_target_passes_redis_prefix_into_pytest_process(
    tmp_path: Path, redis_prefix: str | None
) -> None:
    _require_make_and_sh()
    result = _run_integration_test(tmp_path, redis_prefix, shell=None)
    assert result.returncode == 0, result.stdout + result.stderr
    expected_line = repr(redis_prefix)
    assert result.stdout.count(expected_line) == 2, result.stdout + result.stderr


def test_integration_test_target_passes_redis_prefix_under_dash(tmp_path: Path) -> None:
    if shutil.which("make") is None or not Path("/bin/dash").exists():
        pytest.skip("make or dash not available on this platform")
    result = _run_integration_test(tmp_path, "myprefix:", shell="/bin/dash")
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.count(repr("myprefix:")) == 2, result.stdout + result.stderr
