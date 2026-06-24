from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Result:
    is_malicious: bool
    detected: bool
    attack_class: str | None
    technique_chain: tuple[str, ...]
    benign_category: str | None


def _recall(group: list[Result]) -> float:
    if not group:
        return 0.0
    return sum(1 for item in group if item.detected) / len(group)


def _chain_label(chain: tuple[str, ...]) -> str:
    return "unmutated" if not chain else "+".join(chain)


def _group_by(
    items: list[Result], key: Callable[[Result], Any]
) -> dict[Any, list[Result]]:
    grouped: dict[Any, list[Result]] = {}
    for item in items:
        grouped.setdefault(key(item), []).append(item)
    return grouped


def score(results: list[Result]) -> dict[str, Any]:
    malicious = [item for item in results if item.is_malicious]
    benign = [item for item in results if not item.is_malicious]
    tp = sum(1 for item in malicious if item.detected)
    fn = len(malicious) - tp
    fp = sum(1 for item in benign if item.detected)
    tn = len(benign) - fp

    detection_rate = tp / len(malicious) if malicious else 0.0
    fp_rate = fp / len(benign) if benign else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f_score = (
        2 * precision * detection_rate / (precision + detection_rate)
        if (precision + detection_rate)
        else 0.0
    )

    per_class = {
        key: _recall(group)
        for key, group in _group_by(malicious, lambda item: item.attack_class).items()
    }
    evasion_matrix = {
        _chain_label(key): _recall(group)
        for key, group in _group_by(malicious, lambda item: item.technique_chain).items()
    }
    per_benign_category = {
        key: _recall(group)
        for key, group in _group_by(benign, lambda item: item.benign_category).items()
    }

    return {
        "detection_rate": detection_rate,
        "fp_rate": fp_rate,
        "f_score": f_score,
        "per_class": per_class,
        "evasion_matrix": evasion_matrix,
        "per_benign_category": per_benign_category,
        "totals": {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "n_malicious": len(malicious),
            "n_benign": len(benign),
        },
    }
