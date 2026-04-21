"""Benchmark candidate non-gated prompt-injection classifiers on multilingual data.

Loads the Octavio-Santana multilingual corpus plus any non-English rows from
the existing `load_all()` loaders, then runs each candidate classifier and
reports per-language recall / FPR. The winner becomes the default for
`SecurityConfig.prompt_injection_multilingual_transformer_model`.

Covers non-gated models only. Meta Prompt-Guard (v1 86M, v2 86M/22M) and
vijil/qualifire models are gated and excluded.
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
    (
        "proventra_mdeberta",
        "proventra/mdeberta-v3-base-prompt-injection",
        {"scheme": "softmax", "injection_label_idx": 1},
    ),
    (
        "ri_mmbert",
        "robustintelligence/pi-mmbert-v3.5",
        {"scheme": "multilabel_sigmoid", "injection_label_idx": 0},
    ),
    (
        "madhurjindal_jb_large",
        "madhurjindal/Jailbreak-Detector-Large",
        {"scheme": "softmax", "injection_label_idx": 1},
    ),
    (
        "protectai_v2",
        "protectai/deberta-v3-base-prompt-injection-v2",
        {"scheme": "softmax", "injection_label_idx": 1},
    ),
    (
        "protectai_v1",
        "protectai/deberta-v3-base-prompt-injection",
        {"scheme": "softmax", "injection_label_idx": 1},
    ),
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
    spec: dict[str, Any],
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

    scheme = spec["scheme"]
    idx = int(spec["injection_label_idx"])

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
                if scheme == "multilabel_sigmoid":
                    probs = torch.sigmoid(logits)
                else:
                    probs = torch.softmax(logits, dim=-1)
            inj = probs[:, idx].cpu().tolist()
            results.extend(score >= threshold for score in inj)
        return results

    return classify_batch


def load_multilingual_samples(
    include_english: bool = False,
    deepset_test: bool = True,
) -> list:
    """Multilingual eval corpus.

    - `Octavio-Santana/prompt-injection-attack-detection-multilingual` (all).
    - Non-English rows from `load_deepset(include_test=True)`, `load_spml`,
      `load_safe_guard` to broaden coverage.

    English is excluded by default; pass `include_english=True` to keep EN.
    """
    from dataset_loaders import (
        Sample,
        load_deepset,
        load_dmtrdr_russian,
        load_octavio_multilingual,
        load_safe_guard,
        load_spml,
    )

    seen: set[str] = set()
    out: list[Sample] = []

    streams = [
        load_octavio_multilingual(),
        load_dmtrdr_russian(),
        load_deepset(include_test=deepset_test),
        load_spml(),
        load_safe_guard(),
    ]
    for stream in streams:
        for s in stream:
            if s.sample_id in seen:
                continue
            if not include_english and s.language == "en":
                continue
            if s.language == "xx":
                continue
            seen.add(s.sample_id)
            out.append(s)
    return out


def evaluate_model(
    samples: list,
    classify_batch: ClassifierFn,
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

    min_lang_samples = 30
    min_lang_negatives = 20
    langs_for_macro_recall = [
        (lang, cm)
        for lang, cm in per_lang.items()
        if lang != "all" and cm.total >= min_lang_samples and (cm.tp + cm.fn) > 0
    ]
    langs_for_macro_fpr = [
        (lang, cm)
        for lang, cm in per_lang.items()
        if lang != "all" and (cm.fp + cm.tn) >= min_lang_negatives
    ]
    if langs_for_macro_recall:
        macro_recall = sum(cm.recall for _, cm in langs_for_macro_recall) / len(
            langs_for_macro_recall
        )
        macro_precision = sum(cm.precision for _, cm in langs_for_macro_recall) / len(
            langs_for_macro_recall
        )
        macro_f1 = sum(cm.f1 for _, cm in langs_for_macro_recall) / len(
            langs_for_macro_recall
        )
    else:
        macro_recall = macro_precision = macro_f1 = 0.0
    if langs_for_macro_fpr:
        macro_fpr = sum(cm.fpr for _, cm in langs_for_macro_fpr) / len(
            langs_for_macro_fpr
        )
    else:
        macro_fpr = 0.0

    return {
        "wall_time_seconds": round(elapsed, 2),
        "throughput_samples_per_second": round(len(samples) / elapsed, 1),
        "by_language": {lang: cm.to_dict() for lang, cm in per_lang.items()},
        "macro_across_languages": {
            "recall_languages_counted": [
                lang for lang, _ in langs_for_macro_recall
            ],
            "fpr_languages_counted": [lang for lang, _ in langs_for_macro_fpr],
            "min_samples_per_language": min_lang_samples,
            "min_negatives_per_language_for_fpr": min_lang_negatives,
            "precision": round(macro_precision, 4),
            "recall": round(macro_recall, 4),
            "f1": round(macro_f1, 4),
            "fpr": round(macro_fpr, 4),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--models",
        nargs="+",
        choices=[name for name, _, _ in CANDIDATES],
        default=[name for name, _, _ in CANDIDATES],
    )
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument(
        "--include-english",
        action="store_true",
        help="Include English samples in the eval corpus.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
    )
    args = parser.parse_args()

    device = pick_device()
    print(f"Device: {device}")

    print("Loading multilingual eval corpus...")
    samples = load_multilingual_samples(include_english=args.include_english)
    lang_counts: dict[str, int] = {}
    lang_pos: dict[str, int] = {}
    for s in samples:
        lang_counts[s.language] = lang_counts.get(s.language, 0) + 1
        if s.label:
            lang_pos[s.language] = lang_pos.get(s.language, 0) + 1
    print(f"  {len(samples)} samples total.")
    for lang in sorted(lang_counts):
        n = lang_counts[lang]
        p = lang_pos.get(lang, 0)
        print(f"    {lang}: N={n:<6} pos={p:<5} (pos_rate={p / n:.2f})")

    model_results: dict[str, dict[str, Any]] = {}
    results: dict[str, Any] = {
        "device": device,
        "threshold": args.threshold,
        "batch_size": args.batch_size,
        "include_english": args.include_english,
        "sample_count": len(samples),
        "language_counts": lang_counts,
        "language_positive_counts": lang_pos,
        "models": model_results,
    }

    for alias, repo, spec in CANDIDATES:
        if alias not in args.models:
            continue
        print(f"\n--- {alias} ({repo}) ---")
        clf = build_classifier(repo, spec, args.threshold, device, args.batch_size)
        metrics = evaluate_model(samples, clf)
        model_results[alias] = {"repo": repo, "spec": spec, **metrics}

        overall = metrics["by_language"]["all"]
        macro = metrics["macro_across_languages"]
        print(
            f"{alias:25s}  "
            f"[micro] P={overall['precision']:.3f} "
            f"R={overall['recall']:.3f} "
            f"F1={overall['f1']:.3f} "
            f"FPR={overall['fpr']:.3f}  "
            f"[macro/lang] R={macro['recall']:.3f} FPR={macro['fpr']:.3f}  "
            f"({metrics['throughput_samples_per_second']:.0f} samples/s)"
        )
        for lang in sorted(metrics["by_language"]):
            if lang == "all":
                continue
            cm = metrics["by_language"][lang]
            if cm["total"] < 30:
                continue
            print(
                f"  [{lang}] N={cm['total']} P={cm['precision']:.3f} "
                f"R={cm['recall']:.3f} F1={cm['f1']:.3f} FPR={cm['fpr']:.3f}"
            )

    out = args.out or (Path(__file__).parent / "results" / "multilingual.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print(f"\nResults written to {out}")


if __name__ == "__main__":
    main()
