import importlib

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
