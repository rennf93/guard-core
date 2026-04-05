#!/usr/bin/env python3
"""
Prompt Injection Detection Benchmark

Battle-tests guard-core's prompt injection detection against
real-world datasets:
  - deepset/prompt-injections (662 labeled samples from HuggingFace)
  - Lakera PINT example (8 samples, category-labeled)
  - garak promptinject (combinatorial attack generation from NVIDIA)

Usage:
    uv run python scripts/benchmark_pi.py
    uv run python scripts/benchmark_pi.py --dataset deepset
    uv run python scripts/benchmark_pi.py --sensitivity 0.3 --threshold 0.5
    uv run python scripts/benchmark_pi.py --verbose
    uv run python scripts/benchmark_pi.py --no-cache
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import requests
import yaml

from guard_core.models import SecurityConfig
from guard_core.prompt_injection.pattern_detector import PatternDetector
from guard_core.prompt_injection.scorer import InjectionScorer
from guard_core.prompt_injection.semantic_analyzer import SemanticAnalyzer
from guard_core.prompt_injection.statistical_detector import (
    StatisticalDetector,
)

CACHE_DIR = Path(__file__).resolve().parent.parent / "data" / "benchmark"
CACHE_MAX_AGE_DAYS = 7

HF_ROWS_URL = (
    "https://datasets-server.huggingface.co/rows"
    "?dataset=deepset/prompt-injections"
    "&config=default&split={split}&offset={offset}&length=100"
)

PINT_URL = (
    "https://raw.githubusercontent.com/lakeraai/pint-benchmark"
    "/main/benchmark/data/example-dataset.yaml"
)

GARAK_URL = (
    "https://raw.githubusercontent.com/NVIDIA/garak"
    "/main/garak/resources/promptinject/prompt_data.py"
)


@dataclass
class Sample:
    text: str
    is_attack: bool
    source: str
    category: str = ""


@dataclass
class DatasetResult:
    name: str
    total_attacks: int = 0
    detected_attacks: int = 0
    total_legit: int = 0
    false_positives: int = 0
    missed: list[str] = field(default_factory=list)
    fp_details: list[tuple[str, list[str]]] = field(default_factory=list)
    category_stats: dict[str, tuple[int, int]] = field(default_factory=dict)
    elapsed: float = 0.0


# ── Download helpers ──────────────────────────────────────────


def _ensure_cache_dir() -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _cache_fresh(path: Path) -> bool:
    if not path.exists():
        return False
    age = time.time() - path.stat().st_mtime
    return age < CACHE_MAX_AGE_DAYS * 86400


def _download(url: str, dest: Path, no_cache: bool = False) -> str:
    if not no_cache and _cache_fresh(dest):
        return dest.read_text()
    print(f"  Downloading {url[:80]}...")
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    text = resp.text
    dest.write_text(text)
    return text


# ── Dataset loaders ───────────────────────────────────────────


def load_deepset(no_cache: bool = False) -> list[Sample]:
    _ensure_cache_dir()
    samples: list[Sample] = []

    for split in ("train", "test"):
        cache_path = CACHE_DIR / f"deepset_{split}.json"
        rows: list[dict] = []

        if not no_cache and _cache_fresh(cache_path):
            rows = json.loads(cache_path.read_text())
        else:
            print(f"  Fetching deepset/{split}...")
            offset = 0
            while True:
                url = HF_ROWS_URL.format(split=split, offset=offset)
                resp = requests.get(url, timeout=30)
                resp.raise_for_status()
                data = resp.json()
                batch = [r["row"] for r in data["rows"]]
                rows.extend(batch)
                total = data["num_rows_total"]
                offset += len(batch)
                if offset >= total:
                    break
            cache_path.write_text(json.dumps(rows))

        for row in rows:
            samples.append(
                Sample(
                    text=row["text"],
                    is_attack=row["label"] == 1,
                    source="deepset",
                )
            )

    return samples


def load_pint(no_cache: bool = False) -> list[Sample]:
    _ensure_cache_dir()
    cache_path = CACHE_DIR / "pint_example.yaml"
    content = _download(PINT_URL, cache_path, no_cache)
    entries = yaml.safe_load(content)

    samples: list[Sample] = []
    for entry in entries:
        samples.append(
            Sample(
                text=entry["text"],
                is_attack=entry["label"],
                source="pint",
                category=entry.get("category", ""),
            )
        )
    return samples


def _extract_python_dict(source: str, var_name: str) -> dict:
    """Extract a dict variable from Python source using AST."""
    pattern = rf"^{var_name}\s*=\s*\{{.*?\n\}}"
    match = re.search(pattern, source, re.MULTILINE | re.DOTALL)
    if not match:
        return {}
    try:
        return ast.literal_eval(match.group().split("=", 1)[1].strip())
    except (ValueError, SyntaxError):
        return {}


def load_garak(no_cache: bool = False) -> list[Sample]:
    _ensure_cache_dir()
    cache_path = CACHE_DIR / "garak_prompt_data.py"
    source = _download(GARAK_URL, cache_path, no_cache)

    hijack = _extract_python_dict(source, "goal_hikacking_attacks")
    leaking = _extract_python_dict(source, "prompt_leaking_attacks")
    rogue = _extract_python_dict(source, "rogue_strings")
    escapes = _extract_python_dict(source, "escape_chars")
    delimiters = _extract_python_dict(source, "delimiter_chars")

    samples: list[Sample] = []

    all_attacks = {**hijack, **leaking}
    rogue_values = list(rogue.values()) or ["hacked"]
    escape_values = list(escapes.values()) or [""]
    delimiter_values = list(delimiters.values()) or [""]

    for attack_key, attack_def in all_attacks.items():
        template = attack_def.get("instruction", "")
        if not template:
            continue

        for rs in rogue_values:
            for esc in escape_values:
                for delim in delimiter_values:
                    text = template.replace("{REPLACE_rogue_string}", rs)
                    text = f"{esc}{delim} {text}"
                    text = text.strip()
                    if text:
                        samples.append(
                            Sample(
                                text=text,
                                is_attack=True,
                                source="garak",
                                category=attack_key,
                            )
                        )

    return samples


# ── Scorer setup ──────────────────────────────────────────────


def create_scorer(
    sensitivity: float, threshold: float, stat_weight: float
) -> InjectionScorer:
    config = SecurityConfig(
        enable_redis=False,
        enable_prompt_injection_detection=True,
        prompt_injection_sensitivity=sensitivity,
        prompt_injection_threshold=threshold,
        prompt_injection_statistical_weight=stat_weight,
    )
    return InjectionScorer(
        pattern_detector=PatternDetector(sensitivity=sensitivity),
        statistical_detector=StatisticalDetector(),
        semantic_analyzer=SemanticAnalyzer(),
        config=config,
    )


# ── Benchmark runner ──────────────────────────────────────────


async def benchmark_dataset(
    name: str,
    samples: list[Sample],
    scorer: InjectionScorer,
    verbose: bool = False,
) -> DatasetResult:
    result = DatasetResult(name=name)
    start = time.time()

    for sample in samples:
        score = await scorer.score(sample.text)
        detected = score["is_malicious"]

        if verbose:
            status = (
                ("BLOCKED" if detected else "pass")
                if not sample.is_attack
                else ("CAUGHT" if detected else "MISSED")
            )
            short = sample.text[:65].replace("\n", "\\n")
            print(f"    {status:7s} | {short}")

        cat = sample.category or sample.source
        if cat not in result.category_stats:
            result.category_stats[cat] = (0, 0)

        if sample.is_attack:
            result.total_attacks += 1
            if detected:
                result.detected_attacks += 1
                hits, total = result.category_stats[cat]
                result.category_stats[cat] = (hits + 1, total + 1)
            else:
                result.missed.append(sample.text)
                hits, total = result.category_stats[cat]
                result.category_stats[cat] = (hits, total + 1)
        else:
            result.total_legit += 1
            if detected:
                result.false_positives += 1
                result.fp_details.append((sample.text, score["matched_patterns"]))

    result.elapsed = time.time() - start
    return result


def print_result(result: DatasetResult) -> None:
    print(f"\n{result.name}")
    print("\u2500" * 60)

    if result.total_attacks > 0:
        rate = result.detected_attacks / result.total_attacks * 100
        print(
            f"  Detection rate:  "
            f"{result.detected_attacks}/{result.total_attacks} "
            f"({rate:.1f}%)"
        )

    if result.total_legit > 0:
        fp_rate = result.false_positives / result.total_legit * 100
        print(
            f"  False positive:  "
            f"{result.false_positives}/{result.total_legit} "
            f"({fp_rate:.1f}%)"
        )

    print(f"  Time:            {result.elapsed:.2f}s")

    if result.category_stats and len(result.category_stats) > 1:
        print("\n  Per-category:")
        for cat, (hits, total) in sorted(result.category_stats.items()):
            if total > 0:
                pct = hits / total * 100
                print(f"    {cat:30s}  {hits}/{total} ({pct:.0f}%)")

    if result.missed:
        show = result.missed[:20]
        print(f"\n  Missed ({len(result.missed)}):")
        for text in show:
            short = text[:75].replace("\n", "\\n")
            print(f"    - {short}")
        if len(result.missed) > 20:
            print(f"    ... and {len(result.missed) - 20} more")

    if result.fp_details:
        show = result.fp_details[:10]
        print(f"\n  False positives ({len(result.fp_details)}):")
        for text, patterns in show:
            short = text[:60].replace("\n", "\\n")
            p = patterns[0][:40] if patterns else "?"
            print(f"    - {short}")
            print(f"      triggered: {p}")


def print_summary(results: list[DatasetResult]) -> None:
    total_attacks = sum(r.total_attacks for r in results)
    detected = sum(r.detected_attacks for r in results)
    total_legit = sum(r.total_legit for r in results)
    total_fp = sum(r.false_positives for r in results)

    print("\n" + "=" * 60)
    print("OVERALL SUMMARY")
    print("=" * 60)

    if total_attacks > 0:
        rate = detected / total_attacks * 100
        print(f"  Total attacks:      {total_attacks}")
        print(f"  Detection rate:     {detected}/{total_attacks} ({rate:.1f}%)")

    if total_legit > 0:
        fp_rate = total_fp / total_legit * 100
        print(f"  Total legit:        {total_legit}")
        print(f"  False positive rate: {total_fp}/{total_legit} ({fp_rate:.1f}%)")

    total_time = sum(r.elapsed for r in results)
    print(f"  Total time:         {total_time:.2f}s")
    print("=" * 60)


# ── Main ──────────────────────────────────────────────────────


DATASET_LOADERS = {
    "deepset": ("deepset/prompt-injections (HuggingFace)", load_deepset),
    "pint": ("Lakera PINT example", load_pint),
    "garak": ("garak promptinject (NVIDIA)", load_garak),
}


async def run(args: argparse.Namespace) -> None:
    scorer = create_scorer(args.sensitivity, args.threshold, args.stat_weight)

    print("=" * 60)
    print("PROMPT INJECTION BENCHMARK")
    print(
        f"  sensitivity={args.sensitivity}  "
        f"threshold={args.threshold}  "
        f"stat_weight={args.stat_weight}"
    )
    print("=" * 60)

    datasets_to_run = [args.dataset] if args.dataset else list(DATASET_LOADERS)

    results: list[DatasetResult] = []
    for key in datasets_to_run:
        if key not in DATASET_LOADERS:
            print(f"Unknown dataset: {key}")
            print(f"Available: {', '.join(DATASET_LOADERS)}")
            sys.exit(1)

        label, loader = DATASET_LOADERS[key]
        print(f"\nLoading {label}...")
        samples = loader(no_cache=args.no_cache)
        n_attacks = sum(1 for s in samples if s.is_attack)
        n_legit = len(samples) - n_attacks
        print(f"  {len(samples)} samples ({n_attacks} attacks, {n_legit} legit)")

        result = await benchmark_dataset(label, samples, scorer, args.verbose)
        results.append(result)
        print_result(result)

    if len(results) > 1:
        print_summary(results)


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark prompt injection detection")
    parser.add_argument(
        "--dataset",
        choices=list(DATASET_LOADERS),
        help="Run only this dataset",
    )
    parser.add_argument(
        "--sensitivity",
        type=float,
        default=0.5,
        help="Pattern sensitivity (default: 0.5)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.6,
        help="Detection threshold (default: 0.6)",
    )
    parser.add_argument(
        "--stat-weight",
        type=float,
        default=0.2,
        help="Statistical boost weight (default: 0.2)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print every sample result",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Force re-download datasets",
    )
    args = parser.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
