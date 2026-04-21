"""Benchmark guard_core prompt injection against the `eval_v1` manifest.

Combines five public datasets (jayavibhav, deepset train, gandalf, spml,
safe_guard) into a 70/15/15 stratified split. See `dataset_loaders.py` for
provenance and `manifests/eval_v1.json` for the frozen split.

Default command runs the pattern layers on the `test` split and writes
`results/eval_v1_test.json`. ML layers are opt-in via `--layers`.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from metrics import (
    embedding_classifier,
    evaluate_by_language,
    full_stack_classifier,
    load_split,
    pattern_only_classifier,
    scorer_classifier,
    transformer_classifier,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--split",
        choices=["train", "val", "test"],
        default="test",
        help="Which manifest split to evaluate on.",
    )
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
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
    )
    parser.add_argument(
        "--jayavibhav-max",
        type=int,
        default=20_000,
        help="Cap on jayavibhav samples (stratified). Must match manifest build.",
    )
    args = parser.parse_args()

    out = args.out or (Path(__file__).parent / "results" / f"eval_v1_{args.split}.json")

    print(f"Loading {args.split!r} split from eval_v1 manifest...")
    samples = load_split(args.split, jayavibhav_max=args.jayavibhav_max)
    print(f"  {len(samples)} samples loaded.")

    builders = {
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
        print(f"\n[{layer_name}] building classifier...")
        clf = builders[layer_name]()
        per_lang = evaluate_by_language(samples, clf)
        results[layer_name] = {lang: cm.to_dict() for lang, cm in per_lang.items()}
        overall = per_lang["all"]
        print(
            f"{layer_name:30s}  "
            f"N={overall.total}  "
            f"P={overall.precision:.3f}  R={overall.recall:.3f}  "
            f"F1={overall.f1:.3f}  FPR={overall.fpr:.3f}"
        )
        for lang in sorted(per_lang):
            if lang == "all":
                continue
            cm = per_lang[lang]
            if cm.total < 5:
                continue
            print(
                f"  [{lang}] N={cm.total} P={cm.precision:.3f} "
                f"R={cm.recall:.3f} F1={cm.f1:.3f} FPR={cm.fpr:.3f}"
            )

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print(f"\nResults written to {out}")


if __name__ == "__main__":
    main()
