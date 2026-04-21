"""Benchmark guard_core prompt injection against deepset/prompt-injections."""

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


def load_dataset(max_samples: int | None = None) -> list[tuple[str, bool]]:
    from datasets import load_dataset

    ds = load_dataset("deepset/prompt-injections", split="test")
    samples: list[tuple[str, bool]] = []
    for row in ds:
        text = row["text"]
        label = bool(row["label"])
        samples.append((text, label))
        if max_samples and len(samples) >= max_samples:
            break
    return samples


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-samples", type=int, default=None)
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
        default=Path(__file__).parent / "results" / "deepset.json",
    )
    args = parser.parse_args()

    samples = load_dataset(args.max_samples)
    print(f"Loaded {len(samples)} samples from deepset/prompt-injections")

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
        print(
            f"{layer_name:30s}  "
            f"P={cm.precision:.3f}  R={cm.recall:.3f}  "
            f"F1={cm.f1:.3f}  ACC={cm.accuracy:.3f}  FPR={cm.fpr:.3f}"
        )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2))
    print(f"\nResults written to {args.out}")


if __name__ == "__main__":
    main()
