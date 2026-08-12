import guard_core
import guard_core.sync
from guard_core.protocols import BoundedResponseBodyReader
from guard_core.sync.protocols import SyncBoundedResponseBodyReader


def test_bounded_response_body_reader_importable_from_protocols_package() -> None:
    from guard_core.protocols import BoundedResponseBodyReader as imported

    assert imported is BoundedResponseBodyReader


def test_sync_bounded_response_body_reader_importable_from_sync_protocols_package() -> (
    None
):
    from guard_core.sync.protocols import SyncBoundedResponseBodyReader as imported

    assert imported is SyncBoundedResponseBodyReader


def test_bounded_response_body_reader_accessible_on_top_level_guard_core() -> None:
    assert guard_core.BoundedResponseBodyReader is BoundedResponseBodyReader


def test_sync_bounded_response_body_reader_accessible_on_guard_core_sync() -> None:
    assert (
        guard_core.sync.SyncBoundedResponseBodyReader is SyncBoundedResponseBodyReader
    )


def test_bounded_response_body_reader_listed_in_protocols_all() -> None:
    import guard_core.protocols as protocols_module

    assert "BoundedResponseBodyReader" in protocols_module.__all__


def test_sync_bounded_response_body_reader_listed_in_sync_protocols_all() -> None:
    import guard_core.sync.protocols as sync_protocols_module

    assert "SyncBoundedResponseBodyReader" in sync_protocols_module.__all__


def test_bounded_response_body_reader_listed_in_guard_core_all() -> None:
    assert "BoundedResponseBodyReader" in guard_core.__all__


def test_sync_bounded_response_body_reader_listed_in_guard_core_sync_all() -> None:
    assert "SyncBoundedResponseBodyReader" in guard_core.sync.__all__


def test_bounded_response_body_reader_is_runtime_checkable_protocol() -> None:
    class _Impl:
        def read_body_prefix(self, max_bytes: int) -> bytes:
            return b""

    assert isinstance(_Impl(), BoundedResponseBodyReader)


def test_sync_bounded_response_body_reader_is_runtime_checkable_protocol() -> None:
    class _Impl:
        def read_body_prefix(self, max_bytes: int) -> bytes:
            return b""

    assert isinstance(_Impl(), SyncBoundedResponseBodyReader)
