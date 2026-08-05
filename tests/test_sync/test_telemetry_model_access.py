import ast
from pathlib import Path

import guard_core

PACKAGE_ROOT = Path(guard_core.__file__).resolve().parent
ALLOWED_MODULES = frozenset(
    {
        PACKAGE_ROOT / "_pydantic_plugin_mute.py",
        PACKAGE_ROOT / "models.py",
    }
)
INDIRECTION_CALL_NAMES = frozenset({"__import__", "import_module"})


def _is_type_checking_guard(test: ast.expr) -> bool:
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


def _names_guard_agent(dotted_name: str | None) -> bool:
    return dotted_name is not None and (
        dotted_name == "guard_agent" or dotted_name.startswith("guard_agent.")
    )


def _indirection_call_target(node: ast.Call) -> str | None:
    func = node.func
    is_indirection_call = (
        isinstance(func, ast.Name) and func.id in INDIRECTION_CALL_NAMES
    ) or (isinstance(func, ast.Attribute) and func.attr == "import_module")
    if not is_indirection_call:
        return None
    if not node.args or not isinstance(node.args[0], ast.Constant):
        return None
    value = node.args[0].value
    return value if isinstance(value, str) else None


def _runtime_guard_agent_references(source: str, label: str) -> list[str]:
    tree = ast.parse(source, filename=label)
    violations: list[str] = []

    def visit(node: ast.AST) -> None:
        if isinstance(node, ast.If) and _is_type_checking_guard(node.test):
            for sibling in node.orelse:
                visit(sibling)
            return
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _names_guard_agent(alias.name):
                    violations.append(f"{label}:{node.lineno} imports {alias.name}")
        elif isinstance(node, ast.ImportFrom) and _names_guard_agent(node.module):
            violations.append(f"{label}:{node.lineno} imports from {node.module}")
        elif isinstance(node, ast.Call):
            target = _indirection_call_target(node)
            if target is not None and _names_guard_agent(target):
                violations.append(
                    f"{label}:{node.lineno} calls {ast.unparse(node.func)}({target!r})"
                )
        for child in ast.iter_child_nodes(node):
            visit(child)

    visit(tree)
    return violations


def _guard_core_source_files() -> list[Path]:
    return [
        path
        for path in sorted(PACKAGE_ROOT.rglob("*.py"))
        if path not in ALLOWED_MODULES
        and "sync" not in path.relative_to(PACKAGE_ROOT).parts
    ]


def test_no_module_outside_the_allowlist_uses_a_known_guard_agent_import_shape() -> (
    None
):
    """`guard_core._pydantic_plugin_mute.get_telemetry_model` is the supported
    way to reach a guard-agent telemetry model. This test rejects the import
    shapes anyone has actually used to reach `guard_agent` directly -- a plain
    import, an aliased import, a submodule import followed by attribute
    access, and the `importlib.import_module`/`__import__` indirection
    builtins -- for every module outside the two-file allowlist.

    It cannot catch a dynamically constructed module name (built from string
    concatenation, a variable, or anything else a static scan cannot resolve
    to a literal). This is a lint on the known shapes, not a proof that no
    code path can ever reach `guard_agent`."""
    violations = [
        violation
        for path in _guard_core_source_files()
        for violation in _runtime_guard_agent_references(path.read_text(), str(path))
    ]
    assert violations == []


def test_type_checking_guarded_guard_agent_import_is_not_flagged() -> None:
    """A `guard_agent` import that only exists for type checkers, never at
    runtime, is not a bypass and must not be flagged."""
    source = (
        "from typing import TYPE_CHECKING\n\n"
        "if TYPE_CHECKING:\n"
        "    from guard_agent import AgentConfig\n"
    )
    assert _runtime_guard_agent_references(source, "<type-checking>") == []


def test_scanner_catches_every_synthetic_guard_agent_bypass_shape() -> None:
    """Each shape reaches `guard_agent` at runtime without a plain
    `from guard_agent import SecurityEvent`; the scanner must flag all six."""
    bypass_shapes = {
        "bare attribute access": "import guard_agent\n\nguard_agent.SecurityEvent()\n",
        "getattr indirection": (
            "import guard_agent\n\ngetattr(guard_agent, 'SecurityEvent')()\n"
        ),
        "submodule import then attribute access": (
            "from guard_agent import models\n\nmodels.SecurityEvent()\n"
        ),
        "aliased import": "import guard_agent as ga\n\nga.SecurityEvent()\n",
        "importlib.import_module indirection": (
            "import importlib\n\nimportlib.import_module('guard_agent')\n"
        ),
        "dunder-import indirection": "__import__('guard_agent')\n",
    }
    for label, source in bypass_shapes.items():
        assert _runtime_guard_agent_references(source, label), label
