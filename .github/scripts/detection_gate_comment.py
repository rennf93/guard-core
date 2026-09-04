from __future__ import annotations

import re
import sys
from pathlib import Path

CATEGORY_LINE = re.compile(r"^\s{2}(\w+)\s+(\d+)/(\d+)\s+\(([\d.]+)%\)\s*$")
SUMMARY_LINE = re.compile(r"^=+ .*?(\d+) passed.*=+$")
FAILED_LINE = re.compile(r"^(?:FAILED|ERROR) (\S+)")
ASSERTION_LINE = re.compile(
    r"^E\s+(?:AssertionError: )?(.*(?:regressed|rose|newly flagged).*)$"
)


def _last_section(lines: list[str], header: str) -> dict[str, tuple[str, str]]:
    rows: dict[str, tuple[str, str]] = {}
    start = -1
    for index, line in enumerate(lines):
        if line.startswith(header):
            start = index
    if start < 0:
        return rows
    for line in lines[start + 1 :]:
        match = CATEGORY_LINE.match(line)
        if not match:
            if rows:
                break
            continue
        rows[match.group(1)] = (f"{match.group(2)}/{match.group(3)}", match.group(4))
    return rows


def _last_value(lines: list[str], prefix: str) -> str:
    value = "n/a"
    for line in lines:
        if line.startswith(prefix):
            value = line[len(prefix) :].strip()
    return value


def _count_after(lines: list[str], header: str) -> int:
    start = -1
    for index, line in enumerate(lines):
        if line.startswith(header):
            start = index
    if start < 0:
        return 0
    count = 0
    for line in lines[start + 1 :]:
        if not line.startswith("  "):
            break
        count += 1
    return count


def _verdict_line(lines: list[str]) -> str:
    failed = any(FAILED_LINE.match(line) for line in lines)
    summary = next((m.group(0) for m in map(SUMMARY_LINE.match, lines) if m), "")
    if failed or "failed" in summary:
        return (
            "Gate red: a category regressed against its baseline "
            "or a benign string is newly flagged."
        )
    return (
        "Gate green: no category regressed against its committed baseline "
        "and no benign string is newly flagged."
    )


def _totals_lines(lines: list[str]) -> list[str]:
    total_recall = _last_value(lines, "total recall:")
    total_fp = _last_value(lines, "total fp rate:")
    gaps = _count_after(lines, "known gaps")
    known_fps = _count_after(lines, "known false positives")
    return [
        f"Total recall: {total_recall}. Total false-positive rate: {total_fp}.",
        f"Documented known gaps: {gaps}. Documented known false positives: "
        f"{known_fps}. Both stay in the denominators.",
    ]


def _bullet_block(title: str, items: list[str], code: bool = False) -> list[str]:
    if not items:
        return []
    rendered = [f"- `{item}`" if code else f"- {item}" for item in dict.fromkeys(items)]
    return ["", title, *rendered]


def _table_lines(lines: list[str]) -> list[str]:
    recall = _last_section(lines, "per-category recall")
    if not recall:
        return []
    fp = _last_section(lines, "per-category false-positive attribution")
    rows = ["", "| Category | Recall | False positives |", "|---|---|---|"]
    for category, (fraction, percent) in recall.items():
        fp_fraction, fp_percent = fp.get(category, ("0/0", "0.0"))
        rows.append(
            f"| {category} | {fraction} ({percent}%) | {fp_fraction} ({fp_percent}%) |"
        )
    return rows


def build(report_text: str, job_url: str) -> str:
    lines = report_text.splitlines()
    reasons = [m.group(1) for m in map(ASSERTION_LINE.match, lines) if m]
    failed = [m.group(1) for m in map(FAILED_LINE.match, lines) if m]
    out = [
        "<!-- detection-gate-report -->",
        "## Detection gate report",
        "",
        _verdict_line(lines),
        "",
        *_totals_lines(lines),
        *_bullet_block("Regressions named by the suite:", reasons),
        *_bullet_block("Failed tests:", failed, code=True),
        *_table_lines(lines),
        "",
        f"Full per-case output is in the [job log]({job_url}).",
    ]
    return "\n".join(out) + "\n"


def main() -> int:
    report = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
    Path(sys.argv[3]).write_text(build(report, sys.argv[2]), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
