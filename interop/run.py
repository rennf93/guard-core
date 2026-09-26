import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

GUARD_CORE_ROOT = Path(__file__).resolve().parent.parent
INTEROP_DIR = Path(__file__).resolve().parent
REPORTS_DIR = INTEROP_DIR / "reports"
ECOSYSTEM_ROOT = GUARD_CORE_ROOT.parent.parent
GO_REPO = Path(
    os.environ.get(
        "GUARD_CORE_GO_REPO", str(ECOSYSTEM_ROOT / "Golang" / "guard-core-go")
    )
)
PHP_REPO = Path(
    os.environ.get(
        "GUARD_CORE_PHP_REPO", str(ECOSYSTEM_ROOT / "PHP" / "guard-core-php")
    )
)

PREFIX = "guard_core_interop:"
RATE_WINDOW = 120
PY_HITS_A = 3
GO_HITS_B = 2
PHP_HITS_C = 2
EXEMPT_LIMIT = 2

EXPECTED_A_FIRST = PY_HITS_A + 1
EXPECTED_A_CROSSING = EXPECTED_A_FIRST + 1
EXPECTED_A_PHP = EXPECTED_A_CROSSING + 1
EXPECTED_A_VERIFY = EXPECTED_A_PHP + 1
EXPECTED_A_CROSS_PY = EXPECTED_A_VERIFY + 1
EXPECTED_B_GO = GO_HITS_B
EXPECTED_B_PHP = EXPECTED_B_GO + 1
EXPECTED_B_VERIFY = EXPECTED_B_PHP + 1
EXPECTED_C_VERIFY = PHP_HITS_C + 1

PHASES = [
    "py_write",
    "go_read_then_write",
    "php_read_then_write",
    "py_verify",
    "py_exempt_write",
    "go_exempt_read_then_write",
    "php_exempt_read_then_write",
    "py_exempt_verify",
]
PHASE_PARTICIPANT = {
    "py_write": "python",
    "go_read_then_write": "go",
    "php_read_then_write": "php",
    "py_verify": "python",
    "py_exempt_write": "python",
    "go_exempt_read_then_write": "go",
    "php_exempt_read_then_write": "php",
    "py_exempt_verify": "python",
}


def preflight() -> None:
    for command in (
        ["redis-cli", "-h", "127.0.0.1", "-p", "6379", "ping"],
        ["docker", "info"],
        ["uv", "--version"],
    ):
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise SystemExit(
                f"preflight failed: {' '.join(command)} exited {result.returncode}: "
                f"{result.stderr.strip()}"
            )
    print("preflight: redis ping PONG, docker daemon up, uv available")


def flush_prefix() -> int:
    scanned = subprocess.run(
        ["redis-cli", "--raw", "--scan", "--pattern", f"{PREFIX}*"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    if not scanned:
        return 0
    subprocess.run(
        ["redis-cli", "del", *scanned], capture_output=True, text=True, check=True
    )
    return len(scanned)


def participant_command(
    participant: str, phase: str, report_path: Path, incoming: dict[str, Any]
) -> list[str]:
    if participant == "python":
        return [
            "uv",
            "run",
            "--project",
            str(GUARD_CORE_ROOT),
            "python",
            str(INTEROP_DIR / "py_participant.py"),
        ]
    if participant == "go":
        return [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{GO_REPO}:/app",
            "-v",
            f"{INTEROP_DIR}:/interop",
            "-w",
            "/app",
            "-e",
            "REDIS_HOST=host.docker.internal",
            "-e",
            f"INTEROP_PHASE={phase}",
            "-e",
            f"INTEROP_INPUT={json.dumps(incoming)}",
            "-e",
            f"INTEROP_REPORT_FILE=/interop/reports/{report_path.name}",
            "-e",
            "GOCACHE=/tmp/gocache",
            "golang:1.25-alpine",
            "go",
            "test",
            "-tags",
            "interop",
            "-v",
            "-run",
            "^TestInteropRunner$",
            "-count=1",
            "./guardcore",
        ]
    if participant == "php":
        return [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{PHP_REPO}:/app",
            "-v",
            f"{INTEROP_DIR}:/interop",
            "-w",
            "/app",
            "-e",
            "REDIS_HOST=host.docker.internal",
            "-e",
            f"INTEROP_PHASE={phase}",
            "-e",
            f"INTEROP_INPUT={json.dumps(incoming)}",
            "-e",
            f"INTEROP_REPORT_FILE=/interop/reports/{report_path.name}",
            "php:8.3-cli",
            "php",
            "bin/interop.php",
        ]
    raise SystemExit(f"unknown participant {participant!r}")


def participant_env(
    participant: str, phase: str, incoming: dict[str, Any], report_path: Path
) -> dict[str, str]:
    env = dict(os.environ)
    env["INTEROP_PHASE"] = phase
    env["INTEROP_INPUT"] = json.dumps(incoming)
    env["INTEROP_REPORT_FILE"] = str(report_path)
    if participant == "python":
        env["REDIS_HOST"] = "127.0.0.1"
    return env


def run_phase(phase: str, incoming: dict[str, Any]) -> dict[str, Any]:
    participant = PHASE_PARTICIPANT[phase]
    report_path = REPORTS_DIR / f"{participant}_{phase}.json"
    command = participant_command(participant, phase, report_path, incoming)
    print(f"\n=== phase {phase} ({participant}) ===")
    print(f"$ {' '.join(command)}")
    started = time.monotonic()
    result = subprocess.run(
        command,
        env=participant_env(participant, phase, incoming, report_path),
        capture_output=True,
        text=True,
        timeout=900,
    )
    elapsed = time.monotonic() - started
    print(result.stdout.rstrip())
    if result.stderr.strip():
        print(f"[stderr] {result.stderr.strip()[:2000]}")
    if result.returncode != 0:
        raise SystemExit(
            f"phase {phase} ({participant}) exited {result.returncode} "
            f"after {elapsed:.1f}s"
        )
    if not report_path.exists():
        raise SystemExit(f"phase {phase} did not write {report_path}")
    report: dict[str, Any] = json.loads(report_path.read_text())
    print(
        f"phase {phase}: {report['passed']}/{report['passed'] + report['failed']} "
        f"green in {elapsed:.1f}s"
    )
    return report


EXPECTED = {
    "expected_a_first": EXPECTED_A_FIRST,
    "expected_a_crossing": EXPECTED_A_CROSSING,
    "expected_b_second": EXPECTED_B_GO,
    "expected_a_blocked": EXPECTED_A_PHP,
    "expected_b_blocked": EXPECTED_B_PHP,
    "a_obs": EXPECTED_A_VERIFY,
    "b_obs": EXPECTED_B_VERIFY,
    "c_obs": EXPECTED_C_VERIFY,
    "expected_exempt_limit": EXEMPT_LIMIT,
}


def build_incoming(artifacts: dict[str, str]) -> dict[str, Any]:
    incoming: dict[str, Any] = dict(EXPECTED)
    incoming.update(artifacts)
    return incoming


def verify_ledger(phase: str, report: dict[str, Any]) -> None:
    artifacts = report.get("artifacts", {})
    required = {
        "py_write": ["py_ban_expiry_raw", "legacy_value_raw", "aws_payload_raw"],
        "go_read_then_write": ["go_ban_expiry_raw", "gcp_payload_raw"],
        "php_read_then_write": ["php_ban_expiry_raw", "azure_payload_raw"],
        "py_exempt_write": ["exempt_n_after_py", "exempt_limit"],
        "go_exempt_read_then_write": ["exempt_n_after_go"],
        "php_exempt_read_then_write": ["exempt_n_after_php"],
    }.get(phase, [])
    missing = [key for key in required if key not in artifacts or artifacts[key] == ""]
    if missing:
        raise SystemExit(f"phase {phase} artifacts missing: {missing}")


def aggregate_matrix(
    reports: list[dict[str, Any]],
) -> dict[str, dict[str, dict[str, int]]]:
    matrix: dict[str, dict[str, dict[str, int]]] = {}
    for report in reports:
        for check in report.get("checks", []):
            row = matrix.setdefault(check["scenario"], {})
            cell = row.setdefault(check["direction"], {"passed": 0, "failed": 0})
            cell["passed" if check["passed"] else "failed"] += 1
    return matrix


def print_matrix(matrix: dict[str, dict[str, dict[str, int]]]) -> None:
    directions = sorted({d for row in matrix.values() for d in row})
    scenarios = sorted(matrix)
    width = max([len("scenario")] + [len(s) for s in scenarios]) + 2
    col_width = max([len(d) for d in directions] + [10]) + 2
    header = "scenario".ljust(width) + "".join(d.ljust(col_width) for d in directions)
    print("\n" + "=" * len(header))
    print("INTEROP MATRIX (scenario x direction, passed/failed)")
    print(header)
    print("-" * len(header))
    for scenario in scenarios:
        row = matrix[scenario]
        cells = []
        for direction in directions:
            cell = row.get(direction)
            if cell is None:
                cells.append("-".ljust(col_width))
            else:
                cells.append(f"{cell['passed']}/{cell['failed']}".ljust(col_width))
        print(scenario.ljust(width) + "".join(cells))
    print("-" * len(header))


def main() -> int:
    preflight()
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    removed = flush_prefix()
    print(f"pre-run flush: removed {removed} keys under {PREFIX}*")

    artifacts: dict[str, str] = {}
    reports: list[dict[str, Any]] = []
    started = time.monotonic()
    for phase in PHASES:
        report = run_phase(phase, build_incoming(artifacts))
        verify_ledger(phase, report)
        reports.append(report)
        artifacts.update(report.get("artifacts", {}))
    elapsed = time.monotonic() - started

    removed = flush_prefix()
    print(f"\npost-run flush: removed {removed} keys under {PREFIX}*")

    matrix = aggregate_matrix(reports)
    totals = {
        "passed": sum(r["passed"] for r in reports),
        "failed": sum(r["failed"] for r in reports),
    }
    print_matrix(matrix)
    print(
        f"\ntotal: {totals['passed']}/{totals['passed'] + totals['failed']} "
        f"checks green across {len(reports)} phases in {elapsed:.1f}s"
    )

    last_run = {
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "elapsed_seconds": round(elapsed, 1),
        "redis_prefix": PREFIX,
        "phases": [
            {
                "phase": r["phase"],
                "participant": r["participant"],
                "passed": r["passed"],
                "failed": r["failed"],
                "checks": r["checks"],
            }
            for r in reports
        ],
        "totals": totals,
        "matrix": matrix,
    }
    last_run_path = INTEROP_DIR / "last_run.json"
    last_run_path.write_text(json.dumps(last_run, indent=2))
    print(f"wrote {last_run_path}")

    if totals["failed"] > 0:
        print("RESULT: RED")
        return 1
    print("RESULT: GREEN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
