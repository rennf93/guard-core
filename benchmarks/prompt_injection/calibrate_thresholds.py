"""Calibrate classifier thresholds on the eval_v1 `val` split.

Runs each candidate model once to produce per-sample injection scores on the
val split, then sweeps thresholds to find three operating points:

- `fpr_ceiling`: maximum recall subject to FPR <= 0.01.
- `f1_max`: threshold that maximises F1.
- `youden`: threshold that maximises (TPR - FPR).

Results are written to `results/calibration.json`. The chosen defaults
become the new `SecurityConfig.prompt_injection_transformer_threshold` and
friends in Phase 1c's config-update step.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))


def score_model(
    samples: list,
    repo: str,
    injection_label_idx: int,
    device: str,
    batch_size: int,
) -> list[float]:
    import torch
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
    )

    tokenizer = AutoTokenizer.from_pretrained(repo, revision="main")
    model = AutoModelForSequenceClassification.from_pretrained(repo, revision="main")
    model.eval()
    model.to(device)

    scores: list[float] = []
    texts = [s.text for s in samples]
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
            probs = torch.softmax(logits, dim=-1)
        scores.extend(probs[:, injection_label_idx].cpu().tolist())
    return scores


def sweep_thresholds(
    samples: list,
    scores: list[float],
    thresholds: list[float],
) -> list[dict]:
    """For each threshold, compute P/R/F1/FPR on the given scores."""
    labels = [s.label for s in samples]

    out = []
    for t in thresholds:
        tp = fp = tn = fn = 0
        for lbl, sc in zip(labels, scores, strict=True):
            pred = sc >= t
            if lbl and pred:
                tp += 1
            elif lbl and not pred:
                fn += 1
            elif not lbl and pred:
                fp += 1
            else:
                tn += 1
        p = tp / (tp + fp) if (tp + fp) else 0.0
        r = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        youden = r - fpr
        out.append(
            {
                "threshold": round(t, 3),
                "precision": round(p, 4),
                "recall": round(r, 4),
                "f1": round(f1, 4),
                "fpr": round(fpr, 4),
                "youden": round(youden, 4),
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn,
            }
        )
    return out


def pick_operating_points(sweep: list[dict]) -> dict[str, dict]:
    """Choose four canonical operating points from the sweep.

    - ``fpr_ceiling_0p01``: max recall with FPR <= 0.01. Marked
      ``ceiling_met=False`` if no candidate meets the constraint, in which
      case the lowest-FPR entry is returned as the best-available.
    - ``fpr_ceiling_0p05``: same, with FPR <= 0.05 — a more realistic target
      on adversarial-language eval sets.
    - ``f1_max``: threshold that maximises F1.
    - ``youden``: maximises TPR - FPR (Youden's J statistic).
    """

    def _ceiling(sweep: list[dict], limit: float) -> dict:
        candidates = [s for s in sweep if s["fpr"] <= limit]
        if candidates:
            pick = max(candidates, key=lambda s: s["recall"])
            return {**pick, "ceiling_met": True, "ceiling_limit": limit}
        pick = min(sweep, key=lambda s: s["fpr"])
        return {**pick, "ceiling_met": False, "ceiling_limit": limit}

    return {
        "fpr_ceiling_0p01": _ceiling(sweep, 0.01),
        "fpr_ceiling_0p05": _ceiling(sweep, 0.05),
        "f1_max": max(sweep, key=lambda s: s["f1"]),
        "youden": max(sweep, key=lambda s: s["youden"]),
    }


def pick_device() -> str:
    import torch

    if torch.cuda.is_available():
        return "cuda"
    if torch.backends.mps.is_available():
        return "mps"
    return "cpu"


CANDIDATES = [
    ("protectai_v1", "protectai/deberta-v3-base-prompt-injection", 1),
    ("protectai_v2", "protectai/deberta-v3-base-prompt-injection-v2", 1),
    ("deepset_v3", "deepset/deberta-v3-base-injection", 1),
    ("jackhhao_jb", "jackhhao/jailbreak-classifier", 1),
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--models",
        nargs="+",
        choices=[name for name, _, _ in CANDIDATES],
        default=[name for name, _, _ in CANDIDATES],
    )
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument(
        "--rescore",
        action="store_true",
        help="Ignore cached per-sample scores and re-run inference.",
    )
    parser.add_argument(
        "--jayavibhav-max",
        type=int,
        default=20_000,
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).parent / "results" / "calibration.json",
    )
    args = parser.parse_args()

    from metrics import load_split

    device = pick_device()
    print(f"Device: {device}")

    print("Loading 'val' split...")
    samples = load_split("val", jayavibhav_max=args.jayavibhav_max)
    print(f"  {len(samples)} samples.")

    coarse = [round(x / 100, 3) for x in range(5, 95, 5)]
    fine_tail = [0.95, 0.97, 0.99, 0.995, 0.999]
    thresholds = sorted(set(coarse + fine_tail))

    model_out: dict[str, dict[str, Any]] = {}
    out: dict[str, Any] = {
        "split": "val",
        "device": device,
        "sample_count": len(samples),
        "thresholds": thresholds,
        "models": model_out,
    }

    scores_dir = args.out.parent / "scores"
    scores_dir.mkdir(parents=True, exist_ok=True)

    for alias, repo, label_idx in CANDIDATES:
        if alias not in args.models:
            continue

        scores_path = scores_dir / f"{alias}_val.json"
        if scores_path.exists() and not args.rescore:
            print(f"\nReusing cached scores for {alias} from {scores_path}")
            scores = json.loads(scores_path.read_text())
        else:
            print(f"\nScoring {alias} ({repo})...")
            scores = score_model(samples, repo, label_idx, device, args.batch_size)
            scores_path.write_text(json.dumps(scores))

        sweep = sweep_thresholds(samples, scores, thresholds)
        operating_points = pick_operating_points(sweep)
        model_out[alias] = {
            "repo": repo,
            "sweep": sweep,
            "operating_points": operating_points,
        }
        fpr_op = operating_points["fpr_ceiling_0p01"]
        f1_op = operating_points["f1_max"]
        print(
            f"{alias:20s} FPR<=0.01 at thr={fpr_op['threshold']} "
            f"(R={fpr_op['recall']:.3f} F1={fpr_op['f1']:.3f}) | "
            f"F1-max at thr={f1_op['threshold']} "
            f"(F1={f1_op['f1']:.3f} FPR={f1_op['fpr']:.3f})"
        )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2))
    print(f"\nResults written to {args.out}")


if __name__ == "__main__":
    main()
