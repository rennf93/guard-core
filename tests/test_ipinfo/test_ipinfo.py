import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import maxminddb
import pytest

from guard_core.handlers.ipinfo_handler import IPInfoManager


def _mock_aiohttp(
    content: bytes = b"test data",
    side_effect: Exception | None = None,
) -> MagicMock:
    mock_session = MagicMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)

    if side_effect:
        mock_session.get = AsyncMock(side_effect=side_effect)
    else:
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.read = AsyncMock(return_value=content)
        mock_session.get = AsyncMock(return_value=mock_response)

    return mock_session


@pytest.mark.asyncio
async def test_ipinfo_db(tmp_path: Path) -> None:
    db = IPInfoManager(token="test_token", db_path=tmp_path / "test.mmdb")

    mock_session = _mock_aiohttp(content=b"test data")

    with (
        patch(
            "guard_core.handlers.ipinfo_handler.aiohttp.ClientSession",
            return_value=mock_session,
        ),
        patch("maxminddb.open_database"),
        patch("builtins.open", Mock()),
        patch("os.makedirs"),
    ):
        await db.initialize()

        db.reader = Mock()
        db.reader.get.return_value = {"country": "US"}
        assert db.get_country("1.1.1.1") == "US"


def test_ipinfo_missing_token() -> None:
    with pytest.raises(ValueError):
        IPInfoManager(token="")


async def test_ipinfo_download_failure(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    mock_session = _mock_aiohttp(side_effect=Exception("Download failed"))

    with (
        patch(
            "guard_core.handlers.ipinfo_handler.aiohttp.ClientSession",
            return_value=mock_session,
        ),
        patch.object(IPInfoManager, "_is_db_outdated", return_value=True),
    ):
        await db.initialize()
        assert db.reader is None
        assert not db.db_path.exists()


@pytest.mark.asyncio
async def test_db_initialization_retry(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    mock_session = _mock_aiohttp(side_effect=Exception("First fail"))

    with (
        patch(
            "guard_core.handlers.ipinfo_handler.aiohttp.ClientSession",
            return_value=mock_session,
        ),
        patch("asyncio.sleep") as mock_sleep,
        patch("builtins.open", Mock()),
    ):
        await db.initialize()
        assert mock_sleep.call_count == 2
        assert db.reader is None


@pytest.mark.asyncio
async def test_database_retry_success(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")

    call_count = 0
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.read = AsyncMock(return_value=b"test data")

    async def get_side_effect(*args: Any, **kwargs: Any) -> MagicMock:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise Exception("First fail")
        return mock_response

    mock_session = MagicMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    mock_session.get = AsyncMock(side_effect=get_side_effect)

    mock_file = Mock()
    mock_file_context = Mock()
    mock_file_context.__enter__ = Mock(return_value=mock_file)
    mock_file_context.__exit__ = Mock(return_value=None)
    mock_open = Mock(return_value=mock_file_context)

    with (
        patch(
            "guard_core.handlers.ipinfo_handler.aiohttp.ClientSession",
            return_value=mock_session,
        ),
        patch("builtins.open", mock_open),
        patch("os.makedirs"),
        patch("asyncio.sleep") as mock_sleep,
    ):
        await db._download_database()

        assert call_count == 2
        mock_file.write.assert_called_with(b"test data")
        mock_sleep.assert_called_once_with(1)


def test_db_age_check(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")

    with patch("pathlib.Path.stat") as mock_stat:
        mock_stat.return_value.st_mtime = time.time() - 86401
        assert db._is_db_outdated() is True

        mock_stat.return_value.st_mtime = time.time() - 100
        assert db._is_db_outdated() is False


@pytest.mark.asyncio
async def test_get_country_exception_handling(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.reader = Mock()
    db.reader.get.side_effect = Exception("DB error")

    assert db.get_country("1.1.1.1") is None


def test_db_age_check_missing_db(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "missing.mmdb")
    with patch("pathlib.Path.exists", return_value=False):
        assert db._is_db_outdated() is True


@pytest.mark.asyncio
async def test_real_database_initialization(ipinfo_db_path: Path) -> None:
    ipinfo_db_path.parent.mkdir(parents=True, exist_ok=True)
    with open(ipinfo_db_path, "wb") as f:
        f.write(b"dummy data")

    db = IPInfoManager(token="test_token", db_path=ipinfo_db_path)

    with patch("maxminddb.open_database") as mock_open_db:
        mock_reader = Mock()
        mock_open_db.return_value = mock_reader
        mock_reader.get.return_value = {"country": "US"}

        await db.initialize()
        assert db.reader is not None
        assert db.db_path.exists()

        country = db.get_country("8.8.8.8")
        assert country == "US"
        db.close()


@pytest.mark.asyncio
async def test_close_with_reader(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    mock_reader = Mock()
    db.reader = mock_reader

    db.close()
    mock_reader.close.assert_called_once()


@pytest.mark.asyncio
async def test_close_is_noop_when_reader_is_none(tmp_path: Path) -> None:
    IPInfoManager._instance = None
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.reader = None
    db.close()
    IPInfoManager._instance = None


@pytest.mark.asyncio
async def test_download_database_with_zero_retries_exits_cleanly(
    tmp_path: Path,
) -> None:
    IPInfoManager._instance = None
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db._download_retries = 0
    await db._download_database()
    IPInfoManager._instance = None


@pytest.mark.asyncio
async def test_redis_cache_hit(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.redis_handler = AsyncMock()
    db.redis_handler.get_key.return_value = b"mock_db_data"

    mock_reader = Mock()
    mock_reader.get.return_value = {"country": "US"}

    with patch("maxminddb.open_database", return_value=mock_reader) as mock_open:
        await db.initialize()

        db.redis_handler.get_key.assert_awaited_once_with("ipinfo", "database")

        with open(db.db_path, "rb") as f:
            assert f.read() == b"mock_db_data"

        mock_open.assert_called_once_with(str(db.db_path))
        assert db.reader is mock_reader


@pytest.mark.asyncio
async def test_redis_cache_update(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.redis_handler = AsyncMock()

    mock_session = _mock_aiohttp(content=b"new_db_data")

    with (
        patch(
            "guard_core.handlers.ipinfo_handler.aiohttp.ClientSession",
            return_value=mock_session,
        ),
        patch("maxminddb.open_database"),
    ):
        await db._download_database()

        db.redis_handler.set_key.assert_awaited_once_with(
            "ipinfo", "database", b"new_db_data".decode("latin-1"), ttl=86400
        )


@pytest.mark.asyncio
async def test_redis_initialization_flow(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    mock_redis = AsyncMock()

    with patch.object(db, "initialize", new_callable=AsyncMock) as mock_init:
        await db.initialize_redis(mock_redis)

        assert db.redis_handler is mock_redis
        mock_init.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_country_result_without_country(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.reader = Mock()

    db.reader.get.return_value = {"some_other_field": "value"}

    assert db.get_country("1.1.1.1") is None

    db.reader.get.return_value = None
    assert db.get_country("1.1.1.1") is None


def test_ipinfo_not_initialized() -> None:
    db = IPInfoManager(token="test")
    assert db.is_initialized is False


@pytest.mark.asyncio
async def test_corrupted_db_removal(tmp_path: Path) -> None:
    test_db_path = tmp_path / "country_asn.mmdb"
    db = IPInfoManager(token="test", db_path=test_db_path)
    db.db_path.touch()

    mock_session = _mock_aiohttp(side_effect=Exception("Download failed"))

    with (
        patch(
            "guard_core.handlers.ipinfo_handler.aiohttp.ClientSession",
            return_value=mock_session,
        ),
        patch.object(IPInfoManager, "_is_db_outdated", return_value=True),
    ):
        await db.initialize()
        assert not db.db_path.exists()


@pytest.mark.asyncio
async def test_download_exhausts_retries(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    mock_session = _mock_aiohttp(side_effect=Exception("Download failed"))

    with (
        patch(
            "guard_core.handlers.ipinfo_handler.aiohttp.ClientSession",
            return_value=mock_session,
        ),
        patch("asyncio.sleep"),
    ):
        with pytest.raises(Exception, match="Download failed"):
            await db._download_database()


@pytest.mark.asyncio
async def test_redirect_handling(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")

    mock_session = _mock_aiohttp(content=b"valid_db_content")

    with patch(
        "guard_core.handlers.ipinfo_handler.aiohttp.ClientSession",
        return_value=mock_session,
    ):
        await db._download_database()

        assert db.db_path.exists()
        with open(db.db_path, "rb") as f:
            assert f.read() == b"valid_db_content"

        mock_session.get.assert_called_once()


def test_file_operations(tmp_path: Path) -> None:
    test_path = tmp_path / "test.mmdb"
    test_path.touch()

    mock_reader = Mock()
    mock_reader.__enter__ = Mock(return_value=mock_reader)
    mock_reader.__exit__ = Mock(return_value=None)

    with patch("maxminddb.open_database", return_value=mock_reader):
        with maxminddb.open_database(str(test_path)) as reader:
            assert reader is not None


@pytest.mark.asyncio
async def test_get_country_without_init(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    with pytest.raises(RuntimeError, match="Database not initialized"):
        db.get_country("1.1.1.1")


async def test_initialize_sets_reader_none_when_download_fails_and_db_missing(
    tmp_path,
) -> None:
    from unittest.mock import AsyncMock, patch

    from guard_core.handlers.ipinfo_handler import IPInfoManager

    IPInfoManager._instance = None
    db = tmp_path / "missing.mmdb"
    mgr = IPInfoManager(token="tok", db_path=db)
    mgr.redis_handler = None

    async def _raise(*_a, **_kw):
        raise RuntimeError("download failed")

    with patch.object(mgr, "_download_database", new=AsyncMock(side_effect=_raise)):
        await mgr.initialize()

    assert mgr.reader is None
    assert not db.exists()


async def test_initialize_leaves_reader_unset_when_download_silently_no_file(
    tmp_path,
) -> None:
    # Patch _download_database to succeed without creating the file.
    # Forces the `if self.db_path.exists()` False branch at the end of initialize.
    from unittest.mock import AsyncMock, patch

    from guard_core.handlers.ipinfo_handler import IPInfoManager

    IPInfoManager._instance = None
    db = tmp_path / "quiet.mmdb"
    mgr = IPInfoManager(token="tok", db_path=db)
    mgr.redis_handler = None
    mgr.reader = None

    async def _noop():
        return None

    with patch.object(mgr, "_download_database", new=AsyncMock(side_effect=_noop)):
        await mgr.initialize()

    assert mgr.reader is None


async def test_initialize_redis_cache_miss_falls_through_to_download(
    tmp_path,
) -> None:
    from unittest.mock import AsyncMock, patch

    from guard_core.handlers.ipinfo_handler import IPInfoManager

    IPInfoManager._instance = None
    db = tmp_path / "cached.mmdb"
    mgr = IPInfoManager(token="tok", db_path=db)
    mgr.redis_handler = AsyncMock()
    mgr.redis_handler.get_key = AsyncMock(return_value=None)

    with patch.object(mgr, "_download_database", new=AsyncMock()):
        await mgr.initialize()


async def test_initialize_skips_download_when_db_exists_and_fresh(
    tmp_path,
) -> None:
    from unittest.mock import AsyncMock, MagicMock, patch

    import maxminddb

    from guard_core.handlers.ipinfo_handler import IPInfoManager

    IPInfoManager._instance = None
    db = tmp_path / "fresh.mmdb"
    db.write_bytes(b"stub")

    mgr = IPInfoManager(token="tok", db_path=db)
    mgr.redis_handler = None

    fake_reader = MagicMock()
    fake_reader.close = MagicMock()
    with (
        patch.object(mgr, "_is_db_outdated", return_value=False),
        patch.object(mgr, "_download_database", new=AsyncMock()) as mock_dl,
        patch.object(maxminddb, "open_database", return_value=fake_reader),
    ):
        await mgr.initialize()

    mock_dl.assert_not_awaited()
    IPInfoManager._instance = None


async def test_initialize_redis_delegates_to_initialize() -> None:
    from unittest.mock import AsyncMock, patch

    from guard_core.handlers.ipinfo_handler import IPInfoManager

    IPInfoManager._instance = None
    mgr = IPInfoManager(token="tok")
    redis_handler = AsyncMock()
    with patch.object(mgr, "initialize", new=AsyncMock()) as mock_init:
        await mgr.initialize_redis(redis_handler)
    mock_init.assert_awaited_once()
    assert mgr.redis_handler is redis_handler
