import json
from pathlib import Path
from typing import Any


def build_report(
    metrics: dict[str, Any],
    config_summary: dict[str, Any],
    runtime_seconds: float,
    corpus_fingerprint: str,
) -> dict[str, Any]:
    return {
        **metrics,
        "config": config_summary,
        "runtime_seconds": runtime_seconds,
        "corpus_fingerprint": corpus_fingerprint,
    }


def _rate_table(title: str, rates: dict[str, float]) -> str:
    lines = [f"### {title}", "", "| Key | Rate |", "| --- | --- |"]
    for key in sorted(rates):
        lines.append(f"| {key} | {rates[key]:.3f} |")
    lines.append("")
    return "\n".join(lines)


def _render_markdown(report: dict[str, Any]) -> str:
    totals = report["totals"]
    sections = [
        "# Attack-Simulation Report",
        "",
        f"- Detection rate: {report['detection_rate']:.3f}",
        f"- False-positive rate: {report['fp_rate']:.3f}",
        f"- F-score: {report['f_score']:.3f}",
        f"- Runtime (s): {report['runtime_seconds']:.2f}",
        f"- Corpus fingerprint: {report['corpus_fingerprint']}",
        f"- Totals: {totals}",
        "",
        _rate_table("Recall per attack class", report["per_class"]),
        _rate_table("Evasion-resistance (recall per technique)", report["evasion_matrix"]),
        _rate_table("False-positive rate per benign category", report["per_benign_category"]),
    ]
    return "\n".join(sections)


def write_reports(report: dict[str, Any], out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "report.json"
    md_path = out_dir / "report.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    md_path.write_text(_render_markdown(report), encoding="utf-8")
    return json_path, md_path
