"""Sweep confidence_threshold on the multilingual corpus and pick an operating point.

Loads the same multilingual eval corpus as `benchmark_multilingual.py`, splits
it deterministically 80/20 into val/test stratified by (language, label),
runs the configured multilingual model on the val split at a sweep of
thresholds, picks the threshold that maximises recall subject to FPR ≤
`--fpr-ceiling` (default 0.01), then reports held-out numbers at the chosen
threshold on the test split.

Writes `results/multilingual_calibration.json` with the full sweep + chosen
threshold + held-out numbers. This is the file `SecurityConfig.
prompt_injection_multilingual_transformer_threshold` should be updated to
reflect.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))

ScorerFn = Callable[[list[str]], list[float]]


def pick_device() -> str:
    import torch

    if torch.cuda.is_available():
        return "cuda"
    if torch.backends.mps.is_available():
        return "mps"
    return "cpu"


def build_scorer(
    repo: str,
    scheme: str,
    injection_label_idx: int,
    device: str,
    batch_size: int,
) -> ScorerFn:
    import torch
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
    )

    tokenizer = AutoTokenizer.from_pretrained(repo, revision="main")
    model = AutoModelForSequenceClassification.from_pretrained(repo, revision="main")
    model.eval()
    model.to(device)

    def score_batch(texts: list[str]) -> list[float]:
        scores: list[float] = []
        for start in range(0, len(texts), batch_size):
            batch = texts[start : start + batch_size]
            inputs = tokenizer(
                batch,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True,
            )
            inputs = {k: v.to(device) for k, v in inputs.items()}
            with torch.no_grad():
                logits = model(**inputs).logits
                if scheme == "sigmoid_binary":
                    probs = torch.sigmoid(logits)
                else:
                    probs = torch.softmax(logits, dim=-1)
            scores.extend(probs[:, injection_label_idx].cpu().tolist())
        return scores

    return score_batch


def stratified_split(samples: list, seed: int, val_frac: float) -> tuple[list, list]:
    buckets: dict[tuple[str, bool], list] = {}
    for s in samples:
        buckets.setdefault((s.language, s.label), []).append(s)
    rng = random.Random(seed)
    val: list = []
    test: list = []
    for bucket_samples in buckets.values():
        rng.shuffle(bucket_samples)
        cut = int(len(bucket_samples) * val_frac)
        val.extend(bucket_samples[:cut])
        test.extend(bucket_samples[cut:])
    rng.shuffle(val)
    rng.shuffle(test)
    return val, test


def evaluate_at_threshold(
    samples: list, scores: list[float], threshold: float
) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    for s, score in zip(samples, scores, strict=True):
        predicted = score >= threshold
        if s.label and predicted:
            tp += 1
        elif s.label and not predicted:
            fn += 1
        elif not s.label and predicted:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "threshold": round(threshold, 3),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--model",
        default="proventra/mdeberta-v3-base-prompt-injection",
    )
    parser.add_argument(
        "--scheme",
        choices=["softmax", "sigmoid_binary"],
        default="softmax",
    )
    parser.add_argument("--injection-label-idx", type=int, default=1)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--val-frac", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--corpus",
        choices=["multilingual", "eval_v1"],
        default="multilingual",
        help=(
            "multilingual=non-English eval corpus (default, for the "
            "multilingual transformer); eval_v1=use the eval_v1 manifest's "
            "val split directly (for the English transformer)."
        ),
    )
    parser.add_argument(
        "--fpr-ceiling",
        type=float,
        default=0.01,
        help="Max acceptable FPR when picking threshold.",
    )
    parser.add_argument(
        "--thresholds",
        nargs="+",
        type=float,
        default=[0.3, 0.35, 0.4, 0.45, 0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9],
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
    )
    args = parser.parse_args()

    device = pick_device()
    print(f"Device: {device}")

    if args.corpus == "multilingual":
        from benchmark_multilingual import load_multilingual_samples

        print("Loading multilingual eval corpus...")
        samples = load_multilingual_samples(include_english=False)
        print(f"  {len(samples)} samples total.")
        val, test = stratified_split(samples, seed=args.seed, val_frac=args.val_frac)
    else:
        from metrics import load_split

        print("Loading eval_v1 val+test splits...")
        val = load_split("val")
        test = load_split("test")
        print(f"  val manifest: {len(val)}")
        print(f"  test manifest: {len(test)}")
    print(f"  val={len(val)}  test={len(test)}")

    print(f"Scoring with {args.model!r} (scheme={args.scheme})...")
    score_fn = build_scorer(
        args.model,
        args.scheme,
        args.injection_label_idx,
        device,
        args.batch_size,
    )

    t0 = time.perf_counter()
    val_scores = score_fn([s.text for s in val])
    test_scores = score_fn([s.text for s in test])
    print(f"  scored {len(val) + len(test)} samples in {time.perf_counter() - t0:.1f}s")

    sweep = [evaluate_at_threshold(val, val_scores, t) for t in args.thresholds]

    within_ceiling = [row for row in sweep if row["fpr"] <= args.fpr_ceiling]
    if within_ceiling:
        chosen = max(within_ceiling, key=lambda r: r["recall"])
    else:
        chosen = min(sweep, key=lambda r: r["fpr"])

    chosen_threshold = chosen["threshold"]
    heldout = evaluate_at_threshold(test, test_scores, chosen_threshold)

    print("\nVal sweep:")
    for row in sweep:
        star = "<-- chosen" if row is chosen else ""
        print(
            f"  t={row['threshold']:.2f}  "
            f"P={row['precision']:.3f}  R={row['recall']:.3f}  "
            f"F1={row['f1']:.3f}  FPR={row['fpr']:.3f}  {star}"
        )
    print(
        f"\nHeld-out test split at threshold={chosen_threshold}: "
        f"P={heldout['precision']:.3f}  R={heldout['recall']:.3f}  "
        f"F1={heldout['f1']:.3f}  FPR={heldout['fpr']:.3f}"
    )

    out_path = args.out or (
        Path(__file__).parent / "results" / "multilingual_calibration.json"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(
            {
                "model": args.model,
                "scheme": args.scheme,
                "injection_label_idx": args.injection_label_idx,
                "device": device,
                "seed": args.seed,
                "val_frac": args.val_frac,
                "fpr_ceiling": args.fpr_ceiling,
                "val_size": len(val),
                "test_size": len(test),
                "sweep": sweep,
                "chosen_threshold": chosen_threshold,
                "chosen_val_metrics": chosen,
                "heldout_test_metrics": heldout,
            },
            indent=2,
        )
    )
    print(f"\nResults written to {out_path}")


if __name__ == "__main__":
    main()
