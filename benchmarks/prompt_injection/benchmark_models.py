"""Benchmark candidate transformer classifiers on the eval_v1 split.

Each model is loaded once onto the preferred device (MPS / CUDA / CPU), then
classifies every sample in the split. Writes one `results/models_<split>.json`
file with per-language confusion matrices per model, plus aggregate
`all`-language numbers for fast comparison.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))

ClassifierFn = Callable[[list[str]], list[bool]]

CANDIDATES = [
    ("protectai_v1", "protectai/deberta-v3-base-prompt-injection", 1),
    ("protectai_v2", "protectai/deberta-v3-base-prompt-injection-v2", 1),
    ("deepset_v3", "deepset/deberta-v3-base-injection", 1),
    ("jackhhao_jb", "jackhhao/jailbreak-classifier", 1),
]


def pick_device() -> str:
    import torch

    if torch.cuda.is_available():
        return "cuda"
    if torch.backends.mps.is_available():
        return "mps"
    return "cpu"


def build_classifier(
    repo: str,
    injection_label_idx: int,
    threshold: float,
    device: str,
    batch_size: int,
) -> ClassifierFn:
    import torch
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
    )

    tokenizer = AutoTokenizer.from_pretrained(repo, revision="main")
    model = AutoModelForSequenceClassification.from_pretrained(repo, revision="main")
    model.eval()
    model.to(device)

    def classify_batch(texts: list[str]) -> list[bool]:
        results: list[bool] = []
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
            inj = probs[:, injection_label_idx].cpu().tolist()
            results.extend(score >= threshold for score in inj)
        return results

    return classify_batch


def evaluate_model(
    samples: list,
    classify_batch: ClassifierFn,
    batch_size: int,
) -> dict[str, Any]:
    from metrics import ConfusionMatrix

    texts = [s.text for s in samples]

    t0 = time.perf_counter()
    predictions = classify_batch(texts)
    elapsed = time.perf_counter() - t0

    per_lang: dict[str, ConfusionMatrix] = {"all": ConfusionMatrix()}
    for s, predicted in zip(samples, predictions, strict=True):
        cms = [per_lang["all"], per_lang.setdefault(s.language, ConfusionMatrix())]
        for cm in cms:
            if s.label and predicted:
                cm.tp += 1
            elif s.label and not predicted:
                cm.fn += 1
                if len(cm.fn_samples) < 20:
                    cm.fn_samples.append(s.text[:200])
            elif not s.label and predicted:
                cm.fp += 1
                if len(cm.fp_samples) < 20:
                    cm.fp_samples.append(s.text[:200])
            else:
                cm.tn += 1

    return {
        "wall_time_seconds": round(elapsed, 2),
        "throughput_samples_per_second": round(len(samples) / elapsed, 1),
        "by_language": {lang: cm.to_dict() for lang, cm in per_lang.items()},
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--split",
        choices=["train", "val", "test"],
        default="test",
    )
    parser.add_argument(
        "--models",
        nargs="+",
        choices=[name for name, _, _ in CANDIDATES],
        default=[name for name, _, _ in CANDIDATES],
    )
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument(
        "--jayavibhav-max",
        type=int,
        default=20_000,
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
    )
    args = parser.parse_args()

    from metrics import load_split

    device = pick_device()
    print(f"Device: {device}")

    print(f"Loading {args.split!r} split...")
    samples = load_split(args.split, jayavibhav_max=args.jayavibhav_max)
    print(f"  {len(samples)} samples.")

    model_results: dict[str, dict[str, Any]] = {}
    results: dict[str, Any] = {
        "split": args.split,
        "device": device,
        "threshold": args.threshold,
        "batch_size": args.batch_size,
        "sample_count": len(samples),
        "models": model_results,
    }

    for alias, repo, label_idx in CANDIDATES:
        if alias not in args.models:
            continue
        print(f"\n--- {alias} ({repo}) ---")
        clf = build_classifier(repo, label_idx, args.threshold, device, args.batch_size)
        metrics = evaluate_model(samples, clf, args.batch_size)
        model_results[alias] = {"repo": repo, **metrics}

        overall = metrics["by_language"]["all"]
        print(
            f"{alias:20s}  "
            f"P={overall['precision']:.3f}  "
            f"R={overall['recall']:.3f}  "
            f"F1={overall['f1']:.3f}  "
            f"FPR={overall['fpr']:.3f}  "
            f"throughput={metrics['throughput_samples_per_second']:.0f} samples/s"
        )

    out = args.out or (Path(__file__).parent / "results" / f"models_{args.split}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print(f"\nResults written to {out}")


if __name__ == "__main__":
    main()
