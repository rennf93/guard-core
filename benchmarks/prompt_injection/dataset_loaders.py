"""Dataset loaders for the prompt-injection eval harness.

Each loader returns `Sample` objects with a uniform schema: text, bool label,
language (best-effort via lingua), source dataset name, and a deterministic
sample_id so train/val/test splits can be reproduced without shipping raw data.

Skip policy: samples shorter than 3 chars or longer than 10_000 chars are
dropped (noise at both ends).
"""

from __future__ import annotations

import hashlib
import json
import random
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

_DETECTOR: Any = None


def _detector() -> Any:
    global _DETECTOR
    if _DETECTOR is None:
        from lingua import Language, LanguageDetectorBuilder

        langs = [
            Language.ENGLISH,
            Language.GERMAN,
            Language.SPANISH,
            Language.FRENCH,
            Language.ITALIAN,
            Language.PORTUGUESE,
            Language.DUTCH,
            Language.POLISH,
            Language.RUSSIAN,
            Language.CHINESE,
            Language.JAPANESE,
            Language.KOREAN,
            Language.ARABIC,
            Language.TURKISH,
        ]
        _DETECTOR = LanguageDetectorBuilder.from_languages(*langs).build()
    return _DETECTOR


def detect_language(text: str) -> str:
    """ISO 639-1 code, or 'xx' if unknown / too short."""
    if len(text) < 10:
        return "xx"
    result = _detector().detect_language_of(text)
    if result is None:
        return "xx"
    code: str = result.iso_code_639_1.name.lower()
    return code


@dataclass
class Sample:
    text: str
    label: bool
    language: str
    source: str
    attack_type: str | None = None
    sample_id: str = field(default="")

    def __post_init__(self) -> None:
        if not self.sample_id:
            digest = hashlib.sha1(
                f"{self.source}|{self.text}".encode(), usedforsecurity=False
            ).hexdigest()
            self.sample_id = f"{self.source}:{digest[:16]}"


MIN_LEN = 3
MAX_LEN = 10_000


def _clean(text: Any) -> str | None:
    if not isinstance(text, str):
        return None
    stripped = text.strip()
    if len(stripped) < MIN_LEN or len(stripped) > MAX_LEN:
        return None
    return stripped


def load_jayavibhav(max_samples: int | None = 20_000) -> Iterator[Sample]:
    """English prompt-injection corpus. ~261k train + 65k test upstream.

    Sampled (stratified by label) to `max_samples` total to keep eval tractable.
    """
    from datasets import load_dataset

    ds = load_dataset("jayavibhav/prompt-injection")
    combined: list[tuple[str, int]] = []
    for split_name in ("train", "test"):
        if split_name in ds:
            for row in ds[split_name]:
                text = _clean(row.get("text"))
                if text is not None:
                    combined.append((text, int(row["label"])))

    if max_samples is not None and len(combined) > max_samples:
        rng = random.Random(42)
        pos = [(t, lbl) for t, lbl in combined if lbl == 1]
        neg = [(t, lbl) for t, lbl in combined if lbl == 0]
        per_class = max_samples // 2
        rng.shuffle(pos)
        rng.shuffle(neg)
        combined = pos[:per_class] + neg[:per_class]

    for text, label in combined:
        yield Sample(
            text=text,
            label=bool(label),
            language=detect_language(text),
            source="jayavibhav",
        )


def load_deepset(include_test: bool = False) -> Iterator[Sample]:
    """Deepset prompt-injections — mix of EN and DE.

    Default: train only (546). When the caller also wants to include the
    116-sample canonical test split, set `include_test=True`.
    """
    from datasets import load_dataset

    ds = load_dataset("deepset/prompt-injections")
    splits = ["train"] + (["test"] if include_test else [])
    for split_name in splits:
        for row in ds[split_name]:
            text = _clean(row.get("text"))
            if text is None:
                continue
            yield Sample(
                text=text,
                label=bool(row["label"]),
                language=detect_language(text),
                source=f"deepset_{split_name}",
            )


def load_gandalf() -> Iterator[Sample]:
    """Lakera Gandalf adversarial attempts — all treated as positives."""
    from datasets import load_dataset

    ds = load_dataset("Lakera/gandalf_ignore_instructions", split="train")
    for row in ds:
        text = _clean(row.get("text"))
        if text is None:
            continue
        yield Sample(
            text=text,
            label=True,
            language=detect_language(text),
            source="gandalf",
            attack_type="adversarial_gandalf",
        )


def load_spml() -> Iterator[Sample]:
    """SPML chatbot interactions — uses the User Prompt as text.

    The System Prompt is the LLM's context; samples labelled as injection
    attack this system prompt. We take the user prompt as our input under test.
    """
    from datasets import load_dataset

    ds = load_dataset("reshabhs/SPML_Chatbot_Prompt_Injection", split="train")
    for row in ds:
        text = _clean(row.get("User Prompt"))
        if text is None:
            continue
        raw_label = row.get("Prompt injection", "0")
        label = str(raw_label).strip() == "1"
        yield Sample(
            text=text,
            label=label,
            language=detect_language(text),
            source="spml",
            attack_type="contextual" if label else None,
        )


def load_dmtrdr_russian() -> Iterator[Sample]:
    """dmtrdr/russian_prompt_injections — 22k Russian prompts.

    Labels are jailbreak-technique classes, not binary. We keep only the
    rows whose source column is a recognised prompt-injection corpus
    (Lakera Mosscap, hackaprompt, jackhhao, openai_synthetic) and treat
    them all as positives — the dataset is positive-only by construction.
    Skipped: saladbench / Aegis / Disaster / JailBreakV sources, which
    conflate injection with harmful-content jailbreaks.
    """
    from datasets import load_dataset

    ds = load_dataset("dmtrdr/russian_prompt_injections", split="train")
    injection_sources = {
        "Lakera/mosscap_prompt_injection",
        "hackaprompt/hackaprompt-dataset",
        "jackhhao/jailbreak-classification",
        "openai_synthetic",
    }
    for row in ds:
        source = str(row.get("source", ""))
        if source not in injection_sources:
            continue
        text = _clean(row.get("prompt_ru"))
        if text is None:
            continue
        yield Sample(
            text=text,
            label=True,
            language="ru",
            source="dmtrdr_russian",
            attack_type=str(row.get("class", "")) or None,
        )


def load_octavio_multilingual() -> Iterator[Sample]:
    """Octavio-Santana/prompt-injection-attack-detection-multilingual.

    7924 samples across train+test, ~48% positive, covers DE/IT/ES/FR/PT/HI/RU
    plus EN. Non-gated, binary `text,label,source` schema.
    """
    from datasets import load_dataset

    ds = load_dataset("Octavio-Santana/prompt-injection-attack-detection-multilingual")
    for split_name in ("train", "test"):
        if split_name not in ds:
            continue
        for row in ds[split_name]:
            text = _clean(row.get("text"))
            if text is None:
                continue
            yield Sample(
                text=text,
                label=bool(int(row["label"])),
                language=detect_language(text),
                source=f"octavio_multilingual_{split_name}",
            )


def load_safe_guard() -> Iterator[Sample]:
    """xTRam1/safe-guard-prompt-injection — EN text+label corpus (~10k)."""
    from datasets import load_dataset

    ds = load_dataset("xTRam1/safe-guard-prompt-injection")
    for split_name in ("train", "test"):
        if split_name not in ds:
            continue
        for row in ds[split_name]:
            text = _clean(row.get("text"))
            if text is None:
                continue
            yield Sample(
                text=text,
                label=bool(row["label"]),
                language=detect_language(text),
                source=f"safe_guard_{split_name}",
            )


LOADER_NAMES = (
    "jayavibhav",
    "deepset",
    "gandalf",
    "spml",
    "safe_guard",
)


def load_all(
    exclude_deepset_test: bool = True,
    jayavibhav_max: int | None = 20_000,
) -> list[Sample]:
    """Union of every loader. Returns deduplicated samples."""
    seen: set[str] = set()
    out: list[Sample] = []
    streams: list[Iterable[Sample]] = [
        load_jayavibhav(max_samples=jayavibhav_max),
        load_deepset(include_test=not exclude_deepset_test),
        load_gandalf(),
        load_spml(),
        load_safe_guard(),
    ]
    for stream in streams:
        for s in stream:
            if s.sample_id in seen:
                continue
            seen.add(s.sample_id)
            out.append(s)
    return out


def stratified_split(
    samples: list[Sample],
    train_frac: float = 0.70,
    val_frac: float = 0.15,
    test_frac: float = 0.15,
    seed: int = 42,
) -> dict[str, list[Sample]]:
    """70/15/15 stratified by (language, label)."""
    total = train_frac + val_frac + test_frac
    if abs(total - 1.0) > 1e-6:
        raise ValueError(f"fractions must sum to 1.0, got {total}")

    buckets: dict[tuple[str, bool], list[Sample]] = {}
    for s in samples:
        buckets.setdefault((s.language, s.label), []).append(s)

    rng = random.Random(seed)
    out: dict[str, list[Sample]] = {"train": [], "val": [], "test": []}
    for bucket_samples in buckets.values():
        rng.shuffle(bucket_samples)
        n = len(bucket_samples)
        n_train = int(n * train_frac)
        n_val = int(n * val_frac)
        out["train"].extend(bucket_samples[:n_train])
        out["val"].extend(bucket_samples[n_train : n_train + n_val])
        out["test"].extend(bucket_samples[n_train + n_val :])
    for split in out.values():
        rng.shuffle(split)
    return out


def write_manifest(splits: dict[str, list[Sample]], path: Path) -> None:
    """Write a manifest of sample IDs (and tiny metadata) per split.

    The manifest intentionally does NOT include raw text; loaders regenerate
    the full samples, and the manifest picks which IDs belong to which split.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "version": "1",
        "seed": 42,
        "fractions": {"train": 0.70, "val": 0.15, "test": 0.15},
        "total_samples": sum(len(v) for v in splits.values()),
        "splits": {
            name: {
                "count": len(samples),
                "languages": dict(sorted(_language_counts(samples).items())),
                "positive_rate": sum(1 for s in samples if s.label) / len(samples)
                if samples
                else 0.0,
                "sample_ids": sorted(s.sample_id for s in samples),
            }
            for name, samples in splits.items()
        },
    }
    path.write_text(json.dumps(manifest, indent=2))


def read_manifest(path: Path) -> dict[str, set[str]]:
    """Load a manifest and return `{split_name: {sample_id, ...}}`."""
    manifest = json.loads(path.read_text())
    return {name: set(spec["sample_ids"]) for name, spec in manifest["splits"].items()}


def apply_manifest(
    samples: list[Sample], manifest_ids: dict[str, set[str]]
) -> dict[str, list[Sample]]:
    """Reconstruct splits from a manifest against a freshly loaded sample set.

    Samples in the manifest but missing from the loader are silently dropped
    (upstream dataset may have changed); samples loaded but not in any split
    go to `unassigned`.
    """
    out: dict[str, list[Sample]] = {name: [] for name in manifest_ids}
    out["unassigned"] = []
    by_id = {s.sample_id: s for s in samples}
    for split_name, ids in manifest_ids.items():
        for sid in ids:
            if sid in by_id:
                out[split_name].append(by_id[sid])
    assigned = {sid for ids in manifest_ids.values() for sid in ids}
    for sid, s in by_id.items():
        if sid not in assigned:
            out["unassigned"].append(s)
    return out


def _language_counts(samples: list[Sample]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for s in samples:
        counts[s.language] = counts.get(s.language, 0) + 1
    return counts


def sample_to_dict(s: Sample) -> dict[str, Any]:
    return asdict(s)
