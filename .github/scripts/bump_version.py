from __future__ import annotations

import json
import re
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")


def parse_semver(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def is_latest(new_version: str, existing_versions: list[str]) -> bool:
    new_parsed = parse_semver(new_version)
    for v in existing_versions:
        try:
            if parse_semver(v) > new_parsed:
                return False
        except ValueError:
            continue
    return True


def sorted_versions_descending(versions: list[str]) -> list[str]:
    semver_versions = []
    non_semver = []
    for v in versions:
        try:
            semver_versions.append((parse_semver(v), v))
        except ValueError:
            non_semver.append(v)
    semver_versions.sort(reverse=True)
    return [v for _, v in semver_versions] + non_semver


def update_pyproject_toml(version: str) -> bool:
    path = PROJECT_ROOT / "pyproject.toml"
    content = path.read_text()
    pattern = re.compile(r'^(version\s*=\s*)"[^"]*"', re.MULTILINE)
    match = pattern.search(content)
    if not match:
        print("  ERROR: Could not find version field in pyproject.toml")
        return False
    current = re.search(r'"([^"]*)"', match.group(0))
    if current and current.group(1) == version:
        print(f"  pyproject.toml: already set to {version}")
        return True
    new_content = pattern.sub(f'{match.group(1)}"{version}"', content)
    path.write_text(new_content)
    print(f"  pyproject.toml: updated to {version}")
    return True


def update_mike_yml(version: str) -> bool:
    path = PROJECT_ROOT / ".mike.yml"
    content = path.read_text()
    lines = content.splitlines()

    existing_versions: list[str] = []
    versions_start = -1
    versions_end = -1
    in_versions = False
    for i, line in enumerate(lines):
        if line.startswith("versions:"):
            versions_start = i
            in_versions = True
            continue
        if in_versions:
            stripped = line.strip()
            if stripped.startswith("- "):
                entry = stripped[2:].strip()
                existing_versions.append(entry)
                versions_end = i
            else:
                break

    if versions_start == -1:
        print("  ERROR: Could not find versions list in .mike.yml")
        return False

    if version in existing_versions:
        print(f"  .mike.yml: version {version} already present")
    else:
        semver_versions = [v for v in existing_versions if v != "latest"]
        semver_versions.append(version)
        sorted_versions = sorted_versions_descending(semver_versions)
        if "latest" in existing_versions:
            sorted_versions.append("latest")

        new_version_lines = [f"  - {v}" for v in sorted_versions]
        lines = (
            lines[: versions_start + 1] + new_version_lines + lines[versions_end + 1 :]
        )
        print(f"  .mike.yml: added version {version}")

    semver_only = [v for v in existing_versions + [version] if v != "latest"]
    if is_latest(version, semver_only):
        alias_pattern = re.compile(r"^(\s*latest:\s*).+$")
        for i, line in enumerate(lines):
            match = alias_pattern.match(line)
            if match:
                if line.strip() == f"latest: {version}":
                    print(f"  .mike.yml: latest alias already points to {version}")
                else:
                    lines[i] = f"  latest: {version}"
                    print(f"  .mike.yml: updated latest alias to {version}")
                break

    path.write_text("\n".join(lines) + "\n")
    return True


def update_versions_json(version: str) -> bool:
    path = PROJECT_ROOT / "docs" / "versions" / "versions.json"
    data: dict[str, str] = json.loads(path.read_text())

    if version in data and data.get("latest") == version:
        print(f"  versions.json: already contains {version}")
        return True

    changed = False
    if version not in data:
        data[version] = version
        changed = True
        print(f"  versions.json: added {version}")

    semver_keys = [k for k in data if k != "latest"]
    if is_latest(version, semver_keys):
        if data.get("latest") != version:
            data["latest"] = version
            changed = True
            print(f"  versions.json: updated latest to {version}")

    if not changed:
        print(f"  versions.json: already up to date for {version}")
        return True

    semver_keys = [k for k in data if k != "latest"]
    sorted_keys = sorted_versions_descending(semver_keys)
    if "latest" in data:
        sorted_keys.append("latest")

    ordered: dict[str, str] = {k: data[k] for k in sorted_keys}
    path.write_text(json.dumps(ordered, indent=4) + "\n")
    return True


def _insert_changelog_scaffold(path: Path, version: str, label: str) -> bool:
    content = path.read_text()
    today = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
    header = f"v{version} ({today})"

    if f"v{version} (" in content:
        print(f"  {label}: v{version} entry already exists")
        return True

    scaffold = (
        f"{header}\n"
        f"-------------------\n"
        f"\n"
        f"TITLE (v{version})\n"
        f"------------\n"
        f"\n"
        f"CONTENT\n"
        f"\n"
        f"___\n"
        f"\n"
    )

    version_header_pattern = re.compile(r"^v\d+\.\d+\.\d+ \(", re.MULTILINE)
    match = version_header_pattern.search(content)
    if match:
        insert_pos = match.start()
        new_content = content[:insert_pos] + scaffold + content[insert_pos:]
    else:
        new_content = content.rstrip() + "\n\n" + scaffold

    path.write_text(new_content)
    print(f"  {label}: added v{version} scaffold")
    return True


def update_changelogs(version: str) -> bool:
    changelog = PROJECT_ROOT / "CHANGELOG.md"
    release_notes = PROJECT_ROOT / "docs" / "release-notes.md"

    ok = True
    ok = _insert_changelog_scaffold(changelog, version, "CHANGELOG.md") and ok
    ok = (
        _insert_changelog_scaffold(release_notes, version, "docs/release-notes.md")
        and ok
    )
    return ok


def update_skill_md(version: str) -> bool:
    path = (
        PROJECT_ROOT / "guard_core" / ".agents" / "skills" / "guard-core" / "SKILL.md"
    )
    content = path.read_text()
    pattern = re.compile(r"^Current as of guard-core \d+\.\d+\.\d+\.$", re.MULTILINE)
    match = pattern.search(content)
    if not match:
        print("  ERROR: version marker missing from SKILL.md")
        return False
    if match.group(0) == f"Current as of guard-core {version}.":
        print(f"  SKILL.md: already set to {version}")
        return True
    new_content = pattern.sub(f"Current as of guard-core {version}.", content)
    path.write_text(new_content)
    print(f"  SKILL.md: updated to {version}")
    return True


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: bump_version.py <version>")
        print("  version must be in X.Y.Z format")
        return 1

    version = sys.argv[1]

    if not VERSION_PATTERN.match(version):
        print(f"Error: '{version}' is not a valid version. Expected format: X.Y.Z")
        return 1

    print(f"Bumping version to {version}...\n")

    updaters: list[tuple[str, Callable[[str], bool]]] = [
        ("pyproject.toml", update_pyproject_toml),
        (".mike.yml", update_mike_yml),
        ("docs/versions/versions.json", update_versions_json),
        ("changelogs", update_changelogs),
        ("SKILL.md", update_skill_md),
    ]

    all_ok = True
    for name, updater in updaters:
        try:
            if not updater(version):
                print(f"\n  FAILED: {name}")
                all_ok = False
        except Exception as e:
            print(f"\n  ERROR updating {name}: {e}")
            all_ok = False

    print()
    if all_ok:
        print("Version bump complete.")
    else:
        print("Version bump completed with errors.")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
