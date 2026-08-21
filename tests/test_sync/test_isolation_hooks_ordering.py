from collections.abc import Generator

import pytest

from tests.test_sync import conftest as sync_conftest


@pytest.fixture
def _recording_fixture(
    request: pytest.FixtureRequest,
) -> Generator[None, None, None]:
    assert id(request.node) in sync_conftest._detection_singleton_snapshots
    yield
    assert id(request.node) not in sync_conftest._detection_singleton_snapshots


def test_isolation_hooks_run_outside_the_fixture_stack(
    _recording_fixture: None,
) -> None:
    pass
