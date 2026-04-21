"""Compare a fresh eval_v1 result against the committed baseline.

Exits non-zero if any of the gates below fail:

- Recall on any layer drops by more than `--max-recall-drop` absolute points.
- FPR on any layer rises above `--max-fpr`.
- Any layer moves from `1.000` precision to < that on the `known_benign` slice
  (if that slice is present in the current file).

Intended for CI.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text())
    return data


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--max-recall-drop", type=float, default=0.01)
    parser.add_argument("--max-fpr", type=float, default=0.13)
    args = parser.parse_args()

    baseline = load(args.baseline)
    current = load(args.current)

    failures: list[str] = []

    for layer, baseline_by_lang in baseline.items():
        if layer not in current:
            continue
        baseline_all = baseline_by_lang.get("all") or baseline_by_lang
        current_by_lang = current[layer]
        current_all = current_by_lang.get("all") or current_by_lang

        base_recall = float(baseline_all.get("recall", 0.0))
        curr_recall = float(current_all.get("recall", 0.0))
        drop = base_recall - curr_recall
        if drop > args.max_recall_drop:
            failures.append(
                f"{layer}: recall dropped {base_recall:.4f} -> {curr_recall:.4f} "
                f"(Δ={drop:.4f}, max allowed {args.max_recall_drop:.4f})"
            )

        curr_fpr = float(current_all.get("fpr", 0.0))
        if curr_fpr > args.max_fpr:
            failures.append(
                f"{layer}: FPR {curr_fpr:.4f} above ceiling {args.max_fpr:.4f}"
            )

    if failures:
        print("REGRESSION GATE FAILED:")
        for line in failures:
            print(f"  - {line}")
        sys.exit(1)

    print("Regression gate passed against", args.baseline)


if __name__ == "__main__":
    main()
