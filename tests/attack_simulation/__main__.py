import asyncio
from pathlib import Path

from tests.attack_simulation.harness import run_benchmark
from tests.attack_simulation.reporter import write_reports

_BASE = Path(__file__).parent


def main() -> None:
    report = asyncio.run(run_benchmark(_BASE / "corpus"))
    json_path, md_path = write_reports(report, _BASE / "out")
    print(f"wrote {json_path}")
    print(f"wrote {md_path}")
    print(
        f"detection_rate={report['detection_rate']:.3f} "
        f"fp_rate={report['fp_rate']:.3f} "
        f"runtime_s={report['runtime_seconds']:.2f}"
    )


if __name__ == "__main__":
    main()
