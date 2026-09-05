from __future__ import annotations

import ast
from pathlib import Path

_TESTS_DIR = Path(__file__).parent
_ROOT_CONFTESTS = {
    _TESTS_DIR / "conftest.py",
    _TESTS_DIR / "test_sync" / "conftest.py",
}
_FIXTURE_DECORATOR_NAMES = frozenset(
    {"fixture", "pytest.fixture", "pytest_asyncio.fixture"}
)


def _is_fixture_decorator(node: ast.expr) -> bool:
    return ast.unparse(node).split("(")[0] in _FIXTURE_DECORATOR_NAMES


def _fixture_names(conftest_path: Path) -> list[str]:
    tree = ast.parse(conftest_path.read_text())
    return [
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        if any(_is_fixture_decorator(decorator) for decorator in node.decorator_list)
    ]


def test_nested_conftest_files_define_no_fixtures() -> None:
    nested_conftests = [
        path for path in _TESTS_DIR.rglob("conftest.py") if path not in _ROOT_CONFTESTS
    ]
    assert nested_conftests, "expected at least one nested conftest.py under tests/"

    offenders = {
        str(path.relative_to(_TESTS_DIR)): _fixture_names(path)
        for path in nested_conftests
    }
    assert offenders == {path: [] for path in offenders}
