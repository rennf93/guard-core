import re
from pathlib import Path

from guard_core.models import VALID_BYPASS_CHECKS

_TOKEN_PATTERN = re.compile(r"should_bypass_check(?:_fn)?\(\s*[\"']([a-zA-Z_]+)[\"']")


def _repo_root() -> Path:
    for candidate in Path(__file__).resolve().parents:
        if (candidate / "scripts" / "unasync.py").is_file():
            return candidate
    raise FileNotFoundError("scripts/unasync.py not found above this test file")


def _bypass_tokens_in(root: Path) -> set[str]:
    tokens: set[str] = set()
    for path in root.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        tokens.update(_TOKEN_PATTERN.findall(path.read_text()))
    return tokens


def _assert_matches_valid_bypass_checks(found: set[str], tree_name: str) -> None:
    missing = VALID_BYPASS_CHECKS - found
    unexpected = found - VALID_BYPASS_CHECKS
    assert not missing and not unexpected, (
        f"{tree_name} should_bypass_check tokens drifted from VALID_BYPASS_CHECKS: "
        f"stale entries no longer used={sorted(missing)}, "
        f"new call-site tokens not in the constant={sorted(unexpected)}"
    )


def test_async_tree_bypass_tokens_match_valid_bypass_checks() -> None:
    guard_core_dir = _repo_root() / "guard_core"
    async_files = [
        path
        for path in guard_core_dir.rglob("*.py")
        if path.relative_to(guard_core_dir).parts[0] != "sync"
    ]
    tokens: set[str] = set()
    for path in async_files:
        if "__pycache__" in path.parts:
            continue
        tokens.update(_TOKEN_PATTERN.findall(path.read_text()))
    _assert_matches_valid_bypass_checks(tokens, "async tree")


def test_sync_tree_bypass_tokens_match_valid_bypass_checks() -> None:
    sync_dir = _repo_root() / "guard_core" / "sync"
    tokens = _bypass_tokens_in(sync_dir)
    _assert_matches_valid_bypass_checks(tokens, "sync mirror")
