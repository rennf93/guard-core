import re
from pathlib import Path

from guard_core.models import SecurityConfig

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DOC_PATH = _REPO_ROOT / "docs" / "configuration" / "security-config.md"
_SKILL_CONFIG_PATH = (
    _REPO_ROOT
    / "guard_core"
    / ".agents"
    / "skills"
    / "guard-core"
    / "references"
    / "config.md"
)

_FIELD_CELL_PATTERN = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*)`")


def _doc_field_rows(text: str) -> list[str]:
    names: list[str] = []
    in_field_table = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            in_field_table = False
            continue
        first_cell = stripped.strip("|").split("|", 1)[0].strip()
        if first_cell == "Field":
            in_field_table = True
            continue
        if not in_field_table:
            continue
        if set(first_cell) <= set("-: "):
            continue
        match = _FIELD_CELL_PATTERN.fullmatch(first_cell)
        if match:
            names.append(match.group(1))
    return names


def _security_config_fields() -> set[str]:
    return set(SecurityConfig.model_fields)


def test_every_security_config_field_has_a_docs_table_row() -> None:
    doc_fields = set(_doc_field_rows(_DOC_PATH.read_text()))
    missing = sorted(_security_config_fields() - doc_fields)
    assert not missing, f"SecurityConfig fields missing a row in {_DOC_PATH}: {missing}"


def test_every_docs_table_row_names_a_real_security_config_field() -> None:
    doc_fields = set(_doc_field_rows(_DOC_PATH.read_text()))
    stale = sorted(doc_fields - _security_config_fields())
    assert not stale, (
        f"{_DOC_PATH} documents fields no longer on SecurityConfig: {stale}"
    )


def test_every_security_config_field_is_mentioned_in_skill_config_reference() -> None:
    skill_text = _SKILL_CONFIG_PATH.read_text()
    unmentioned = sorted(
        field for field in _security_config_fields() if f"`{field}`" not in skill_text
    )
    assert not unmentioned, (
        f"{_SKILL_CONFIG_PATH} has no backticked mention of: {unmentioned}"
    )
