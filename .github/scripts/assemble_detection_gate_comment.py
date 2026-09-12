"""Assemble the sharded detection-gate PR comment from per-shard reports.

Each detection-gate shard uploads its pytest output as an artifact named
detection-report-<shard>. The aggregator job downloads them into one
directory and runs this script: it renders every shard through the same
fragment builder the single-job gate used, strips the per-fragment HTML
marker, and posts one comment carrying a single marker plus an overall
verdict derived from the shard results.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from detection_gate_comment import MARKER, build


def _shard_reports(reports_dir: Path) -> list[tuple[str, Path]]:
    pairs: list[tuple[str, Path]] = []
    for artifact_dir in sorted(reports_dir.iterdir()):
        if not artifact_dir.is_dir() or not artifact_dir.name.startswith(
            "detection-report-"
        ):
            continue
        shard = artifact_dir.name[len("detection-report-") :]
        for report in sorted(artifact_dir.glob("*.txt")):
            pairs.append((shard, report))
    return pairs


def assemble(reports_dir: Path, job_url: str, shard_result: str) -> str:
    parts = [
        MARKER,
        "## Detection gate report",
        "",
        (
            "All detection gate shards passed."
            if shard_result == "success"
            else "One or more detection gate shards failed — the failed "
            "shards are named in the job summary."
        ),
        "",
    ]
    for shard, report in _shard_reports(reports_dir):
        fragment = build(report.read_text(encoding="utf-8", errors="replace"), job_url)
        lines = [
            line
            for line in fragment.splitlines()
            if line.strip() not in (MARKER, "## Detection gate report")
        ]
        parts.append(f"### Shard `{shard}`")
        parts.extend(lines)
        parts.append("")
    return "\n".join(parts) + "\n"


def main() -> int:
    reports_dir = Path(sys.argv[1])
    shard_result = os.environ.get("SHARD_RESULT", "unknown")
    Path(sys.argv[2]).write_text(
        assemble(reports_dir, os.environ.get("JOB_URL", ""), shard_result),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
