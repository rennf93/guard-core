import ast
from pathlib import Path

import guard_core

PACKAGE_ROOT = Path(guard_core.__file__).resolve().parent
MUTE_MODULE = PACKAGE_ROOT / "_pydantic_plugin_mute.py"
FORBIDDEN_MODULES = frozenset({"guard_agent", "guard_agent.models"})
FORBIDDEN_NAMES = frozenset({"SecurityEvent", "SecurityMetric", "EventBatch"})


def _guard_core_source_files() -> list[Path]:
    return [
        path
        for path in sorted(PACKAGE_ROOT.rglob("*.py"))
        if path != MUTE_MODULE and "sync" not in path.relative_to(PACKAGE_ROOT).parts
    ]


def _direct_telemetry_model_imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    return [
        f"{path}:{node.lineno} imports {alias.name} from {node.module}"
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module in FORBIDDEN_MODULES
        for alias in node.names
        if alias.name in FORBIDDEN_NAMES
    ]


def test_no_module_outside_the_mute_module_imports_telemetry_models_directly() -> None:
    """Every guard-core module must obtain SecurityEvent/SecurityMetric/EventBatch
    through `guard_core._pydantic_plugin_mute.get_telemetry_model`, which mutes
    pydantic plugin instrumentation first. A direct `from guard_agent import ...`
    anywhere else in guard_core/ would bypass the mute for that call site."""
    violations = [
        violation
        for path in _guard_core_source_files()
        for violation in _direct_telemetry_model_imports(path)
    ]
    assert violations == []
