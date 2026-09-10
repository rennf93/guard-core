from collections.abc import Callable, Iterable
from functools import partial
from itertools import chain


def _prefixed_repeat_probe(
    prefix: str, unit: str, stray: str, flood: bool, length: int
) -> str:
    if length <= len(prefix):
        return prefix[:length]
    remaining = length - len(prefix)
    tail_length = max(1, remaining // 2) if flood else 1
    body_length = remaining - tail_length
    body = (unit * (body_length // len(unit) + 1))[:body_length]
    return prefix + body + stray * tail_length


def _prefixed_unit_builders(
    prefixes: list[str], units: Iterable[tuple[str, str]]
) -> list[Callable[[int], str]]:
    if not prefixes:
        return []
    unique_units: dict[tuple[str, str], None] = {}
    for unit in units:
        unique_units[unit] = None
        if len(prefixes) * len(unique_units) * 2 > 4096:
            raise TimeoutError(
                "Pattern validation prefixed-probe candidate budget exceeded"
            )
    return [
        partial(_prefixed_repeat_probe, prefix, unit, stray, flood)
        for prefix in prefixes
        for unit, stray in unique_units
        for flood in (False, True)
    ]


_GROUP_PREFIX_CANDIDATE_LIMIT = 8192


def _group_probe_candidates(
    group_pairs: list[tuple[str, str]],
    strays: list[str],
    choose_stray: Callable[[str], str],
) -> dict[tuple[str, str, str], None]:
    unit_strays: dict[str, str] = {}
    candidates: dict[tuple[str, str, str], None] = {}
    for prefix, unit in group_pairs:
        if unit not in unit_strays:
            unit_strays[unit] = choose_stray(unit)
        for stray in chain((unit_strays[unit],), strays):
            candidates[(prefix, unit, stray)] = None
            candidates[("", unit, stray)] = None
            if len(candidates) > _GROUP_PREFIX_CANDIDATE_LIMIT:
                raise TimeoutError(
                    "Pattern validation group-probe candidate budget exceeded"
                )
    return candidates


def _group_unit_builders(
    group_pairs: list[tuple[str, str]],
    strays: list[str],
    choose_stray: Callable[[str], str],
) -> list[Callable[[int], str]]:
    return [
        partial(_prefixed_repeat_probe, prefix, unit, stray, flood)
        for prefix, unit, stray in _group_probe_candidates(
            group_pairs, strays, choose_stray
        )
        for flood in (False, True)
    ]
