import itertools
import random
from collections.abc import Iterator
from typing import Any

from tests.redaction_gate.axes import AXIS_ORDER, BASELINE_AXES, SURFACES, gated_pool


def generate_ofat(
    surfaces: list[str],
) -> tuple[list[tuple[str, dict[str, Any]]], set[Any]]:
    seen: set[Any] = set()
    cases: list[tuple[str, dict[str, Any]]] = []
    for surface in surfaces:
        for axis in AXIS_ORDER:
            for value in gated_pool(axis, surface):
                axes = dict(BASELINE_AXES)
                axes[axis] = value
                key = (surface, tuple(sorted(axes.items())))
                if key in seen:
                    continue
                seen.add(key)
                cases.append((surface, axes))
    return cases, seen


def generate_random(
    surfaces: list[str], seed: int, count: int, seen: set[Any]
) -> list[tuple[str, dict[str, Any]]]:
    rng = random.Random(seed)
    cases: list[tuple[str, dict[str, Any]]] = []
    attempts = 0
    max_attempts = count * 20 + 200
    while len(cases) < count and attempts < max_attempts:
        attempts += 1
        surface = rng.choice(surfaces)
        axes = {axis: rng.choice(gated_pool(axis, surface)) for axis in AXIS_ORDER}
        key = (surface, tuple(sorted(axes.items())))
        if key in seen:
            continue
        seen.add(key)
        cases.append((surface, axes))
    return cases


def full_product_count(surfaces: list[str]) -> int:
    total = 0
    for surface in surfaces:
        n = 1
        for axis in AXIS_ORDER:
            n *= len(gated_pool(axis, surface))
        total += n
    return total


def generate_full_product(
    surfaces: list[str], seen: set[Any]
) -> Iterator[tuple[str, dict[str, Any]]]:
    for surface in surfaces:
        pools = [gated_pool(axis, surface) for axis in AXIS_ORDER]
        for combo in itertools.product(*pools):
            axes = dict(zip(AXIS_ORDER, combo, strict=True))
            key = (surface, tuple(sorted(axes.items())))
            if key in seen:
                continue
            seen.add(key)
            yield surface, axes


def build_grammar_plan(
    seeds: list[int], limit: int
) -> tuple[list[tuple[str, dict[str, Any]]], int, int]:
    ofat_cases, seen = generate_ofat(SURFACES)
    full_count = full_product_count(SURFACES)
    if limit == 0:
        plan = ofat_cases + list(generate_full_product(SURFACES, seen))
        return plan, len(ofat_cases), full_count
    plan = list(ofat_cases)
    random_budget = max(0, limit - len(ofat_cases))
    for seed in seeds:
        plan.extend(generate_random(SURFACES, seed, random_budget, seen))
    return plan, len(ofat_cases), full_count
