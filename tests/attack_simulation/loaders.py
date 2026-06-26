from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Seed:
    seed_id: str
    attack_class: str
    payload: str
    source: str
    license: str


@dataclass(frozen=True)
class BenignSample:
    text: str
    category: str
    source: str
    license: str


def _parse_file(path: Path) -> tuple[str, str, list[str]]:
    source = "unknown"
    license_name = "unknown"
    payloads: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("# source:"):
            source = line.split(":", 1)[1].strip()
        elif line.startswith("# license:"):
            license_name = line.split(":", 1)[1].strip()
        elif line and not line.startswith("#"):
            payloads.append(line)
    return source, license_name, payloads


def load_seeds(seeds_dir: Path) -> list[Seed]:
    seeds: list[Seed] = []
    for path in sorted(seeds_dir.glob("*.txt")):
        attack_class = path.stem
        source, license_name, payloads = _parse_file(path)
        for index, payload in enumerate(payloads):
            seeds.append(
                Seed(
                    f"{attack_class}-{index}",
                    attack_class,
                    payload,
                    source,
                    license_name,
                )
            )
    return seeds


def load_benign(benign_dir: Path) -> list[BenignSample]:
    samples: list[BenignSample] = []
    for path in sorted(benign_dir.glob("*.txt")):
        category = path.stem
        source, license_name, payloads = _parse_file(path)
        for payload in payloads:
            samples.append(BenignSample(payload, category, source, license_name))
    return samples
