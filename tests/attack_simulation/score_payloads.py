import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from guard_core.models import SecurityConfig

from tests.attack_simulation.runner import SCAN_IP, detection_manager


async def score_payloads(
    payloads: list[str], config: SecurityConfig | None = None
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    async with detection_manager(config) as manager:
        for payload in payloads:
            detection = await manager.detect(
                payload, ip_address=SCAN_IP, context="unknown"
            )
            results.append(
                {
                    "payload": payload,
                    "detected": bool(detection["is_threat"]),
                    "threat_score": float(detection["threat_score"]),
                }
            )
    return results


def main(argv: list[str]) -> None:
    in_path, out_path = Path(argv[0]), Path(argv[1])
    payloads = json.loads(in_path.read_text(encoding="utf-8"))
    results = asyncio.run(score_payloads(payloads))
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main(sys.argv[1:])
