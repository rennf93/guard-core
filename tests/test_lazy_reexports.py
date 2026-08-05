import importlib
import importlib.util
import inspect
from pathlib import Path
from types import ModuleType

import pytest

import guard_core
import guard_core.handlers
import guard_core.sync
import guard_core.sync.handlers


def test_every_handlers_all_name_importable_directly() -> None:
    for name in guard_core.handlers.__all__:
        module = importlib.import_module("guard_core.handlers")
        assert hasattr(module, name)


def test_every_handlers_all_name_resolves_via_getattr() -> None:
    for name in guard_core.handlers.__all__:
        assert getattr(guard_core.handlers, name) is not None


def test_every_handlers_all_name_appears_in_dir() -> None:
    listed = dir(guard_core.handlers)
    for name in guard_core.handlers.__all__:
        assert name in listed


def test_every_guard_core_all_name_importable_directly() -> None:
    for name in guard_core.__all__:
        module = importlib.import_module("guard_core")
        assert hasattr(module, name)


def test_every_guard_core_all_name_resolves_via_getattr() -> None:
    for name in guard_core.__all__:
        assert getattr(guard_core, name) is not None


def test_every_guard_core_all_name_appears_in_dir() -> None:
    listed = dir(guard_core)
    for name in guard_core.__all__:
        assert name in listed


def test_every_sync_handlers_all_name_importable_directly() -> None:
    for name in guard_core.sync.handlers.__all__:
        module = importlib.import_module("guard_core.sync.handlers")
        assert hasattr(module, name)


def test_every_sync_handlers_all_name_resolves_via_getattr() -> None:
    for name in guard_core.sync.handlers.__all__:
        assert getattr(guard_core.sync.handlers, name) is not None


def test_every_sync_handlers_all_name_appears_in_dir() -> None:
    listed = dir(guard_core.sync.handlers)
    for name in guard_core.sync.handlers.__all__:
        assert name in listed


def test_every_guard_core_sync_all_name_importable_directly() -> None:
    for name in guard_core.sync.__all__:
        module = importlib.import_module("guard_core.sync")
        assert hasattr(module, name)


def test_every_guard_core_sync_all_name_resolves_via_getattr() -> None:
    for name in guard_core.sync.__all__:
        assert getattr(guard_core.sync, name) is not None


def test_every_guard_core_sync_all_name_appears_in_dir() -> None:
    listed = dir(guard_core.sync)
    for name in guard_core.sync.__all__:
        assert name in listed


def test_unknown_attribute_raises_on_guard_core() -> None:
    with pytest.raises(AttributeError):
        guard_core.__getattr__("does_not_exist")


def test_unknown_attribute_raises_on_handlers() -> None:
    with pytest.raises(AttributeError):
        guard_core.handlers.__getattr__("does_not_exist")


def test_unknown_attribute_raises_on_sync() -> None:
    with pytest.raises(AttributeError):
        guard_core.sync.__getattr__("does_not_exist")


def test_unknown_attribute_raises_on_sync_handlers() -> None:
    with pytest.raises(AttributeError):
        guard_core.sync.handlers.__getattr__("does_not_exist")


def _find_unasync_script() -> Path:
    for candidate in Path(__file__).resolve().parents:
        script_path = candidate / "scripts" / "unasync.py"
        if script_path.is_file():
            return script_path
    raise FileNotFoundError("scripts/unasync.py not found above this test file")


def _load_unasync_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("unasync", _find_unasync_script())
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _shared_source_module_names() -> set[str]:
    unasync = _load_unasync_generator()
    skip_src: set[str] = unasync.__dict__["SKIP_SRC"]
    return {f"guard_core.{Path(filename).stem}" for filename in skip_src}


def test_every_guard_core_sync_all_name_sources_from_sync_or_shared_module() -> None:
    shared_modules = _shared_source_module_names()
    module_by_name = guard_core.sync._MODULE_BY_NAME
    for name in guard_core.sync.__all__:
        source_module = module_by_name[name]
        assert (
            source_module.startswith("guard_core.sync")
            or source_module in shared_modules
        ), f"{name} sources from {source_module}"


def _public_callables(obj: object) -> list[tuple[str, object]]:
    if inspect.isfunction(obj) or inspect.ismethod(obj):
        return [(obj.__name__, obj)]
    target = obj if inspect.isclass(obj) else type(obj)
    return [
        (member_name, member)
        for member_name, member in inspect.getmembers(
            target, predicate=inspect.isfunction
        )
        if not member_name.startswith("_")
    ]


def test_guard_core_sync_exports_have_no_coroutine_function_callables() -> None:
    for name in guard_core.sync.__all__:
        obj = getattr(guard_core.sync, name)
        for member_name, member in _public_callables(obj):
            assert not inspect.iscoroutinefunction(member), (
                f"{name}.{member_name} is a coroutine function"
            )
