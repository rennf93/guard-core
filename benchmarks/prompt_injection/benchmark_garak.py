"""Benchmark guard_core prompt injection against garak probes."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from metrics import (
    embedding_classifier,
    evaluate,
    full_stack_classifier,
    pattern_only_classifier,
    scorer_classifier,
    transformer_classifier,
)


def load_dataset(probes_dir: Path) -> list[tuple[str, bool]]:
    if not probes_dir.exists():
        raise FileNotFoundError(
            f"garak probes directory not found at {probes_dir}. "
            "Point --probes at garak/data/promptinject/"
        )
    samples: list[tuple[str, bool]] = []
    for jsonl in probes_dir.rglob("*.jsonl"):
        with jsonl.open() as fh:
            for line in fh:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                text = row.get("prompt") or row.get("text") or row.get("attack")
                if text is None:
                    continue
                samples.append((str(text), True))
    return samples


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--probes", type=Path, required=True)
    parser.add_argument(
        "--layers",
        nargs="+",
        default=["pattern_only", "pattern_plus_statistical"],
        choices=[
            "pattern_only",
            "pattern_plus_statistical",
            "embedding",
            "transformer",
            "full_stack",
        ],
        help=(
            "Layers to evaluate. 'embedding', 'transformer', and 'full_stack' "
            "require the optional 'guard-core[prompt_injection]' extra."
        ),
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).parent / "results" / "garak.json",
    )
    args = parser.parse_args()

    samples = load_dataset(args.probes)
    print(f"Loaded {len(samples)} garak probes (all labeled as attacks)")

    all_layers = {
        "pattern_only": pattern_only_classifier,
        "pattern_plus_statistical": lambda: scorer_classifier(
            enable_statistical_boost=True
        ),
        "embedding": embedding_classifier,
        "transformer": transformer_classifier,
        "full_stack": full_stack_classifier,
    }

    results: dict[str, dict[str, object]] = {}
    for layer_name in args.layers:
        clf = all_layers[layer_name]()
        cm = evaluate(samples, clf)
        results[layer_name] = cm.to_dict()
        miss_rate = cm.fn / cm.total if cm.total else 0.0
        print(
            f"{layer_name:30s}  Detected={cm.tp}/{cm.total}  Miss rate={miss_rate:.3f}"
        )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2))
    print(f"\nResults written to {args.out}")


if __name__ == "__main__":
    main()
