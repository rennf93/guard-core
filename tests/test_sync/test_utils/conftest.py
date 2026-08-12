import pytest

from guard_core.sync import utils


@pytest.fixture(autouse=True)
def _zero_straddle_overlap_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    def _zero_overlap() -> int:
        return 0

    monkeypatch.setattr(utils, "_straddle_overlap_bytes", _zero_overlap)
