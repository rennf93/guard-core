import pytest

from guard_core.sync._utils import body_reader


@pytest.fixture(autouse=True)
def _zero_straddle_overlap_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    def _zero_overlap() -> int:
        return 0

    monkeypatch.setattr(body_reader, "_straddle_overlap_bytes", _zero_overlap)
