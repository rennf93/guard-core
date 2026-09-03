from pathlib import Path

from radon.metrics import mi_rank, mi_visit

_REPO_ROOT = Path(__file__).resolve().parent.parent
_GUARD_CORE = _REPO_ROOT / "guard_core"


def _source_files() -> list[Path]:
    return sorted(
        path for path in _GUARD_CORE.rglob("*.py") if "__pycache__" not in path.parts
    )


def test_every_module_is_maintainability_rank_a() -> None:
    offenders = []
    for path in _source_files():
        source = path.read_text()
        score = mi_visit(source, True)
        rank = mi_rank(score)
        if rank != "A":
            offenders.append(f"{path.relative_to(_REPO_ROOT)}: {rank} ({score:.2f})")

    assert not offenders, (
        "Modules below maintainability rank A "
        "(run `radon mi guard_core -s` for details):\n" + "\n".join(offenders)
    )
