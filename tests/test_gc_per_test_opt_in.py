import inspect
from unittest.mock import Mock

import pytest

from tests import conftest


def test_collect_garbage_after_test_runs_gc_collect_when_env_var_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(conftest, "GUARD_TESTS_GC_PER_TEST", True)
    collect = Mock()
    monkeypatch.setattr(conftest.gc, "collect", collect)

    fixture_function = inspect.unwrap(conftest._collect_garbage_after_test)
    generator = fixture_function()
    next(generator)
    with pytest.raises(StopIteration):
        next(generator)

    collect.assert_called_once()
