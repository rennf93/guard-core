import hashlib
import time
from pathlib import Path
from typing import Any

from guard_core.models import SecurityConfig
from tests.attack_simulation.loaders import load_benign, load_seeds
from tests.attack_simulation.metrics import Result, score
from tests.attack_simulation.mutations import generate_variants
from tests.attack_simulation.reporter import build_report
from tests.attack_simulation.runner import (
    build_detection_config,
    detection_manager,
    scan,
)

_DETECTION_FIELDS = (
    "detection_compiler_timeout",
    "detection_max_content_length",
    "detection_preserve_attack_patterns",
    "detection_semantic_threshold",
    "detection_anomaly_threshold",
    "detection_slow_pattern_threshold",
    "detection_monitor_history_size",
    "detection_max_tracked_patterns",
)


def summarize_config(config: SecurityConfig) -> dict[str, Any]:
    return {field: getattr(config, field) for field in _DETECTION_FIELDS}


def fingerprint_corpus(corpus_dir: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(corpus_dir.rglob("*.txt")):
        digest.update(path.read_bytes())
    return digest.hexdigest()


async def run_benchmark(
    corpus_dir: Path, config: SecurityConfig | None = None
) -> dict[str, Any]:
    config = config or build_detection_config()
    seeds = load_seeds(corpus_dir / "seeds")
    benign = load_benign(corpus_dir / "benign")
    results: list[Result] = []
    started = time.perf_counter()
    async with detection_manager(config) as manager:
        for seed in seeds:
            for variant in generate_variants(
                seed.seed_id, seed.attack_class, seed.payload
            ):
                detected = await scan(manager, variant.payload)
                results.append(
                    Result(
                        True,
                        detected,
                        variant.attack_class,
                        variant.technique_chain,
                        None,
                    )
                )
        for sample in benign:
            detected = await scan(manager, sample.text)
            results.append(Result(False, detected, None, (), sample.category))
    runtime_seconds = time.perf_counter() - started
    return build_report(
        score(results),
        summarize_config(config),
        runtime_seconds,
        fingerprint_corpus(corpus_dir),
    )
