import json
from collections import Counter
from pathlib import Path

from tests.redaction_gate.axes import AXES_POOLS, axis_value_str
from tests.redaction_gate.runner import CaseResult

AxisSummary = dict[str, dict[str, dict[str, int]]]


def print_result_counts(results: list[CaseResult]) -> list[CaseResult]:
    counts = Counter(r.outcome for r in results)
    leaks = [r for r in results if r.outcome == "LEAK"]

    print("\n=== RESULT ===")
    print(f"total cases: {len(results)}")
    print(f"OK (detected + redacted): {counts['OK']}")
    print(
        "NOT_DETECTED (trigger never fired, silence != redaction): "
        f"{counts['NOT_DETECTED']}"
    )
    print(f"ERROR (scenario raised, moving tree): {counts['ERROR']}")
    print(
        "UNASSIGNED_TOKEN (secret planted as a bare token with no key=value "
        f"assignment; excluded from exit code): {counts['UNASSIGNED_TOKEN']}"
    )
    print(f"LEAK: {counts['LEAK']}")
    return leaks


def build_axis_summary(results: list[CaseResult]) -> AxisSummary:
    summary: AxisSummary = {}
    for res in results:
        if res.axes is None:
            continue
        for axis, value in {**res.axes, "surface": res.surface}.items():
            axis_str = axis_value_str(axis, value) if axis in AXES_POOLS else str(value)
            bucket = summary.setdefault(axis, {}).setdefault(
                axis_str,
                {"total": 0, "leak": 0, "not_detected": 0, "unassigned_token": 0},
            )
            bucket["total"] += 1
            if res.outcome == "LEAK":
                bucket["leak"] += 1
            elif res.outcome == "NOT_DETECTED":
                bucket["not_detected"] += 1
            elif res.outcome == "UNASSIGNED_TOKEN":
                bucket["unassigned_token"] += 1
    return summary


def print_axis_summary(results: list[CaseResult]) -> None:
    summary = build_axis_summary(results)
    print("\n=== AXIS SUMMARY (grammar phase only) ===")
    for axis in sorted(summary):
        print(f"\n[{axis}]")
        for value in sorted(summary[axis]):
            stats = summary[axis][value]
            print(
                f"  {value:<28} total={stats['total']:<6} "
                f"leak={stats['leak']:<4} not_detected={stats['not_detected']:<4} "
                f"unassigned_token={stats['unassigned_token']}"
            )


def print_first_leaks(leaks: list[CaseResult], limit: int = 50) -> None:
    print(f"\n=== FIRST {min(limit, len(leaks))} LEAKS ===")
    for res in leaks[:limit]:
        print(f"\ncase_id: {res.case_id}")
        print(f"surface: {res.surface}  axes: {res.axes}")
        print(f"secret: {res.secret}")
        for channel, snippet in res.leaks:
            print(f"  LEAK[{channel}]: {snippet!r}")


def write_ledger(results: list[CaseResult], json_out: str) -> None:
    out_path = Path(json_out)
    out_path.write_text(
        json.dumps(
            [
                {
                    "case_id": r.case_id,
                    "phase": r.phase,
                    "surface": r.surface,
                    "axes": r.axes,
                    "config_variant": r.config_variant,
                    "secret": r.secret,
                    "detected": r.detected,
                    "outcome": r.outcome,
                    "leaks": r.leaks,
                }
                for r in results
            ],
            indent=2,
            default=str,
        )
    )
    print(f"\nfull case ledger written to {out_path}")
