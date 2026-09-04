import argparse
import asyncio
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generative secret-redaction probe for guard-core"
    )
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument(
        "--seeds",
        type=str,
        default=None,
        help="comma-separated seed list, e.g. '0,1'; overrides --seed",
    )
    parser.add_argument(
        "--limit", type=int, default=3000, help="0 means the full cartesian product"
    )
    parser.add_argument(
        "--json-out", type=str, default=str(_HERE / "genprobe_results.json")
    )
    parser.add_argument("--tmp-dir", type=str, default=str(_HERE / "scenario_tmp"))
    return parser.parse_args(argv)


def _seed_list(args: argparse.Namespace) -> list[int]:
    if args.seeds:
        return [int(part.strip()) for part in args.seeds.split(",") if part.strip()]
    return [args.seed]


def _bootstrap_repo_import_path() -> None:
    repo_root = str(Path.cwd())
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)


def _assert_guard_core_in_repo() -> None:
    import guard_core

    guard_core_path = Path(guard_core.__file__).resolve()
    repo_root = Path.cwd().resolve()
    assert guard_core_path.is_relative_to(repo_root), (
        f"guard_core.__file__={guard_core.__file__!r} is not inside repo "
        f"{repo_root!r}; run this from the repo root with the documented uv run command"
    )
    print(f"guard_core.__file__ = {guard_core.__file__}")


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    _bootstrap_repo_import_path()
    _assert_guard_core_in_repo()

    from tests.redaction_gate.pipeline import run_probe

    return asyncio.run(
        run_probe(
            seeds=_seed_list(args),
            limit=args.limit,
            json_out=args.json_out,
            tmp_dir=args.tmp_dir,
        )
    )


if __name__ == "__main__":
    sys.exit(main())
