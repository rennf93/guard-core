import logging
from pathlib import Path
from typing import Any

import tests.test_sensitive_data_invariant as INV_ASYNC
import tests.test_sync.test_sensitive_data_invariant as INV_SYNC
from tests.redaction_gate.axes import BASELINE_AXES, SURFACES, variant_for_surface
from tests.redaction_gate.capture import CaptureHandler, logfire_patch_stack
from tests.redaction_gate.generation import build_grammar_plan
from tests.redaction_gate.reporting import (
    print_axis_summary,
    print_first_leaks,
    print_result_counts,
    write_ledger,
)
from tests.redaction_gate.runner import (
    CaseResult,
    build_module_variants,
    run_component_scenario_async,
    run_component_scenario_sync,
    run_fixed_case_async,
    run_fixed_case_sync,
    run_grammar_case,
)
from tests.redaction_gate.state_axis import run_state_phase

ModuleVariants = dict[str, tuple[Any, Any, Any]]


async def _run_fixed_phase(capture: CaptureHandler, tmp_dir: Path) -> list[CaseResult]:
    results: list[CaseResult] = []
    print("running fixed-case replay (Phase A: reuse of the invariant test's cases)...")
    for async_case in INV_ASYNC._CASES:
        results.append(await run_fixed_case_async(async_case, capture))
    for sync_case in INV_SYNC._CASES:
        results.append(run_fixed_case_sync(sync_case, capture))
    for async_scenario in INV_ASYNC._COMPONENT_SCENARIOS:
        results.append(
            await run_component_scenario_async(async_scenario, capture, tmp_dir)
        )
    for sync_scenario in INV_SYNC._COMPONENT_SCENARIOS:
        results.append(run_component_scenario_sync(sync_scenario, capture, tmp_dir))
    print(f"  fixed-case replay done: {len(results)} cases")
    return results


async def _run_knob_sweep_phase(
    async_variants: ModuleVariants,
    sync_variants: ModuleVariants,
    capture: CaptureHandler,
) -> list[CaseResult]:
    print("running config-knob sweep (passive_mode / log_suspicious_level)...")
    results: list[CaseResult] = []
    for surface in SURFACES:
        for variant_name in ("passive", "debug_level"):
            axes = dict(BASELINE_AXES)
            res = await run_grammar_case(
                surface,
                axes,
                {
                    **async_variants,
                    variant_for_surface(surface): async_variants[variant_name],
                },
                {
                    **sync_variants,
                    variant_for_surface(surface): sync_variants[variant_name],
                },
                capture,
            )
            res.case_id = f"{res.case_id}__cfg.{variant_name}"
            res.config_variant = variant_name
            results.append(res)
    print(f"  config-knob sweep done: {len(results)} cases")
    return results


async def _run_grammar_phase(
    plan: list[tuple[str, dict[str, Any]]],
    async_variants: ModuleVariants,
    sync_variants: ModuleVariants,
    capture: CaptureHandler,
) -> list[CaseResult]:
    results: list[CaseResult] = []
    for count, (surface, axes) in enumerate(plan, start=1):
        results.append(
            await run_grammar_case(
                surface, axes, async_variants, sync_variants, capture
            )
        )
        if count % 250 == 0:
            print(f"  ... {count} grammar cases run")
    print(f"grammar phase done: {len(results)} cases")
    return results


def _print_grammar_plan_info(
    seeds: list[int], limit: int, ofat_count: int, full_count: int
) -> None:
    print(f"one-dimension-at-a-time coverage: {ofat_count} cases (always included)")
    if limit == 0:
        print(
            f"--limit 0: full cartesian product size = {full_count} "
            "(this will take a long time)"
        )
    else:
        print(f"random fill with seeds={seeds}, limit={limit} per seed")


def _setup_capture() -> tuple[logging.Logger, CaptureHandler]:
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    capture = CaptureHandler()
    root_logger.addHandler(capture)
    return root_logger, capture


async def run_probe(seeds: list[int], limit: int, json_out: str, tmp_dir: str) -> int:
    tmp_path = Path(tmp_dir)
    tmp_path.mkdir(parents=True, exist_ok=True)
    root_logger, capture = _setup_capture()

    all_results: list[CaseResult] = []
    with logfire_patch_stack():
        all_results += await _run_fixed_phase(capture, tmp_path)
        all_results += await run_state_phase(capture)

        async_variants = build_module_variants(INV_ASYNC)
        sync_variants = build_module_variants(INV_SYNC)
        all_results += await _run_knob_sweep_phase(
            async_variants, sync_variants, capture
        )

        plan, ofat_count, full_count = build_grammar_plan(seeds, limit)
        _print_grammar_plan_info(seeds, limit, ofat_count, full_count)
        all_results += await _run_grammar_phase(
            plan, async_variants, sync_variants, capture
        )

    root_logger.removeHandler(capture)

    leaks = print_result_counts(all_results)
    print_axis_summary(all_results)
    print_first_leaks(leaks)
    write_ledger(all_results, json_out)
    return 1 if leaks else 0
