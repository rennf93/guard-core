import ipaddress
import itertools
from collections.abc import Generator
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.cloud_handler import (
    cloud_handler,
    fetch_aws_ip_ranges,
    fetch_azure_ip_ranges,
    fetch_gcp_ip_ranges,
)
from guard_core.sync.handlers.redis_handler import RedisManager


def _mock_aiohttp_response(
    json_data: dict | None = None,
    text_data: str | None = None,
    status: int = 200,
) -> MagicMock:
    mock_response = MagicMock()
    mock_response.status_code = status
    mock_response.raise_for_status = MagicMock()
    if json_data is not None:
        mock_response.json = MagicMock(return_value=json_data)
    if text_data is not None:
        mock_response.text = text_data
    mock_response.content = b""
    return mock_response


def _mock_session(*responses: MagicMock) -> MagicMock:
    mock_session = MagicMock()
    mock_session.get = MagicMock(
        side_effect=list(responses) if len(responses) > 1 else responses[0]
    )
    mock_session.__enter__ = MagicMock(return_value=mock_session)
    mock_session.__exit__ = MagicMock(return_value=None)
    return mock_session


@pytest.fixture
def mock_aiohttp_session() -> Generator[MagicMock, None]:
    with patch("guard_core.sync.handlers.cloud_handler.requests.Session") as mock_cls:
        mock_sess = MagicMock()
        mock_sess.__enter__ = MagicMock(return_value=mock_sess)
        mock_sess.__exit__ = MagicMock(return_value=None)
        mock_cls.return_value = mock_sess
        yield mock_sess


def test_fetch_aws_ip_ranges(mock_aiohttp_session: MagicMock) -> None:
    mock_resp = _mock_aiohttp_response(
        json_data={
            "prefixes": [
                {"ip_prefix": "192.168.0.0/24", "service": "AMAZON"},
                {"ip_prefix": "10.0.0.0/8", "service": "EC2"},
            ]
        }
    )
    mock_aiohttp_session.get = MagicMock(return_value=mock_resp)

    result = fetch_aws_ip_ranges()
    assert ipaddress.IPv4Network("192.168.0.0/24") in result
    assert ipaddress.IPv4Network("10.0.0.0/8") not in result


def test_fetch_gcp_ip_ranges(mock_aiohttp_session: MagicMock) -> None:
    mock_resp = _mock_aiohttp_response(
        json_data={
            "prefixes": [
                {"ipv4Prefix": "172.16.0.0/12"},
                {"ipv6Prefix": "2001:db8::/32"},
            ]
        }
    )
    mock_aiohttp_session.get = MagicMock(return_value=mock_resp)

    result = fetch_gcp_ip_ranges()
    assert ipaddress.IPv4Network("172.16.0.0/12") in result
    assert ipaddress.IPv6Network("2001:db8::/32") in result
    assert len(result) == 2


def test_fetch_azure_ip_ranges(mock_aiohttp_session: MagicMock) -> None:
    mock_html_resp = _mock_aiohttp_response(
        text_data="""
        Some HTML content
        manually <a href="https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20230515.json">
        More HTML content
        """
    )
    mock_json_resp = _mock_aiohttp_response(
        json_data={
            "values": [
                {"properties": {"addressPrefixes": ["192.168.1.0/24", "2001:db8::/32"]}}
            ]
        }
    )
    mock_aiohttp_session.get = MagicMock(side_effect=[mock_html_resp, mock_json_resp])

    result = fetch_azure_ip_ranges()
    assert ipaddress.IPv4Network("192.168.1.0/24") in result
    assert ipaddress.IPv6Network("2001:db8::/32") in result
    assert len(result) == 2


def test_cloud_ip_ranges() -> None:
    with (
        patch(
            "guard_core.sync.handlers.cloud_handler.fetch_aws_ip_ranges",
            return_value={ipaddress.IPv4Network("192.168.0.0/24")},
        ),
        patch(
            "guard_core.sync.handlers.cloud_handler.fetch_gcp_ip_ranges",
            return_value={ipaddress.IPv4Network("172.16.0.0/12")},
        ),
        patch(
            "guard_core.sync.handlers.cloud_handler.fetch_azure_ip_ranges",
            return_value={ipaddress.IPv4Network("10.0.0.0/8")},
        ),
    ):
        cloud_handler._refresh_providers()

        assert cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})
        assert not cloud_handler.is_cloud_ip("192.168.0.1", {"GCP"})
        assert cloud_handler.is_cloud_ip("172.16.0.1", {"GCP"})
        assert cloud_handler.is_cloud_ip("10.0.0.1", {"Azure"})
        assert not cloud_handler.is_cloud_ip("8.8.8.8", {"AWS", "GCP", "Azure"})


def test_cloud_ip_refresh() -> None:
    with (
        patch(
            "guard_core.sync.handlers.cloud_handler.fetch_aws_ip_ranges",
        ) as mock_aws,
        patch(
            "guard_core.sync.handlers.cloud_handler.fetch_gcp_ip_ranges",
            return_value={ipaddress.IPv4Network("172.16.0.0/12")},
        ),
        patch(
            "guard_core.sync.handlers.cloud_handler.fetch_azure_ip_ranges",
            return_value={ipaddress.IPv4Network("10.0.0.0/8")},
        ),
    ):
        mock_aws.return_value = {ipaddress.IPv4Network("192.168.0.0/24")}

        cloud_handler._refresh_providers()
        assert cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})

        mock_aws.return_value = {ipaddress.IPv4Network("192.168.1.0/24")}
        cloud_handler.refresh()

        assert not cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})
        assert cloud_handler.is_cloud_ip("192.168.1.1", {"AWS"})


def test_cloud_ip_refresh_subset() -> None:
    with (
        patch(
            "guard_core.sync.handlers.cloud_handler.fetch_aws_ip_ranges",
            return_value={ipaddress.IPv4Network("192.168.0.0/24")},
        ),
        patch(
            "guard_core.sync.handlers.cloud_handler.fetch_gcp_ip_ranges",
            return_value={ipaddress.IPv4Network("172.16.0.0/12")},
        ),
        patch(
            "guard_core.sync.handlers.cloud_handler.fetch_azure_ip_ranges",
            return_value={ipaddress.IPv4Network("10.0.0.0/8")},
        ),
    ):
        providers = ["AWS", "GCP", "Azure"]
        for r in range(1, 4):
            for combo in itertools.combinations(providers, r):
                provider_set = set(combo)
                cloud_handler.ip_ranges = {}
                cloud_handler._refresh_providers(provider_set)

                if "AWS" in provider_set:
                    assert cloud_handler.is_cloud_ip("192.168.0.1")
                if "GCP" in provider_set:
                    assert cloud_handler.is_cloud_ip("172.16.0.1")
                if "Azure" in provider_set:
                    assert cloud_handler.is_cloud_ip("10.0.0.1")

                if "AWS" not in provider_set:
                    assert not cloud_handler.is_cloud_ip("192.168.0.1")
                if "GCP" not in provider_set:
                    assert not cloud_handler.is_cloud_ip("172.16.0.1")
                if "Azure" not in provider_set:
                    assert not cloud_handler.is_cloud_ip("10.0.0.1")


def test_cloud_ip_ranges_error_handling() -> None:
    with (
        patch(
            "guard_core.sync.handlers.cloud_handler.fetch_aws_ip_ranges",
            side_effect=Exception("AWS error"),
        ),
        patch(
            "guard_core.sync.handlers.cloud_handler.fetch_gcp_ip_ranges",
            side_effect=Exception("GCP error"),
        ),
        patch(
            "guard_core.sync.handlers.cloud_handler.fetch_azure_ip_ranges",
            side_effect=Exception("Azure error"),
        ),
    ):
        assert not cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})
        assert not cloud_handler.is_cloud_ip("172.16.0.1", {"GCP"})
        assert not cloud_handler.is_cloud_ip("10.0.0.1", {"Azure"})


def test_cloud_ip_ranges_invalid_ip() -> None:
    assert not cloud_handler.is_cloud_ip("invalid_ip", {"AWS", "GCP", "Azure"})


def test_fetch_aws_ip_ranges_error(mock_aiohttp_session: MagicMock) -> None:
    mock_aiohttp_session.get = MagicMock(side_effect=Exception("API failure"))
    result = fetch_aws_ip_ranges()
    assert result == set()


def test_fetch_gcp_ip_ranges_error(mock_aiohttp_session: MagicMock) -> None:
    mock_resp = _mock_aiohttp_response()
    mock_resp.json = MagicMock(side_effect=Exception("Invalid JSON"))
    mock_aiohttp_session.get = MagicMock(return_value=mock_resp)
    result = fetch_gcp_ip_ranges()
    assert result == set()


def test_cloud_manager_refresh_handling() -> None:
    with (
        patch(
            "guard_core.sync.handlers.cloud_handler.fetch_aws_ip_ranges",
            return_value={ipaddress.IPv4Network("192.168.0.0/24")},
        ),
        patch(
            "guard_core.sync.handlers.cloud_handler.fetch_gcp_ip_ranges",
            return_value={ipaddress.IPv4Network("172.16.0.0/12")},
        ),
        patch(
            "guard_core.sync.handlers.cloud_handler.fetch_azure_ip_ranges",
            return_value={ipaddress.IPv4Network("10.0.0.0/8")},
        ),
    ):
        cloud_handler.ip_ranges["AWS"] = set()
        assert len(cloud_handler.ip_ranges["AWS"]) == 0

        cloud_handler.refresh()
        assert len(cloud_handler.ip_ranges["AWS"]) == 1


def test_is_cloud_ip_ipv6() -> None:
    assert not cloud_handler.is_cloud_ip("2001:db8::1", {"AWS"})


def test_fetch_azure_ip_ranges_url_not_found(
    mock_aiohttp_session: MagicMock,
) -> None:
    mock_resp = _mock_aiohttp_response(text_data="HTML without download link")
    mock_aiohttp_session.get = MagicMock(return_value=mock_resp)
    result = fetch_azure_ip_ranges()
    assert result == set()


def test_fetch_azure_ip_ranges_download_failure(
    mock_aiohttp_session: MagicMock,
) -> None:
    mock_html_resp = _mock_aiohttp_response(
        text_data='<a href="https://download.microsoft.com/valid.json">'
    )
    mock_download_resp = MagicMock()
    mock_download_resp.raise_for_status = MagicMock(
        side_effect=Exception("Download failed")
    )
    mock_aiohttp_session.get = MagicMock(
        side_effect=[mock_html_resp, mock_download_resp]
    )
    result = fetch_azure_ip_ranges()
    assert result == set()


def test_cloud_ip_redis_caching(security_config_redis: SecurityConfig) -> None:
    with (
        patch(
            "guard_core.sync.handlers.cloud_handler.fetch_aws_ip_ranges",
        ) as mock_aws,
        patch(
            "guard_core.sync.handlers.cloud_handler.fetch_gcp_ip_ranges",
            return_value=set(),
        ),
        patch(
            "guard_core.sync.handlers.cloud_handler.fetch_azure_ip_ranges",
            return_value=set(),
        ),
    ):
        mock_aws.return_value = {ipaddress.IPv4Network("192.168.0.0/24")}

        redis_handler = RedisManager(security_config_redis)
        redis_handler.initialize()

        cloud_handler.initialize_redis(redis_handler)

        assert cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})
        import json as _json

        cached_raw = redis_handler.get_key("guard:cloud_ip", "AWS")
        assert _json.loads(cached_raw) == ["192.168.0.0/24"]

        mock_aws.return_value = {ipaddress.IPv4Network("192.168.1.0/24")}
        cloud_handler.refresh_async()

        redis_handler.delete("guard:cloud_ip", "AWS")
        cloud_handler.refresh_async()

        mock_aws.side_effect = Exception("API Error")
        cloud_handler.refresh_async()
        assert cloud_handler.is_cloud_ip("192.168.1.1", {"AWS"})

        cloud_handler._store = None
        cloud_handler.redis_handler = None
        cloud_handler.refresh_async()

        redis_handler.close()


def test_cloud_ip_redis_cache_hit(
    security_config_redis: SecurityConfig,
) -> None:
    import json as _json

    redis_handler = RedisManager(security_config_redis)
    redis_handler.initialize()

    redis_handler.set_key("guard:cloud_ip", "AWS", _json.dumps(["192.168.0.0/24"]))

    cloud_handler.initialize_redis(redis_handler)

    with patch(
        "guard_core.sync.handlers.cloud_handler.fetch_aws_ip_ranges",
    ) as mock_aws:
        assert cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})
        mock_aws.assert_not_called()

    redis_handler.close()


def test_cloud_ip_redis_sync_async(
    security_config_redis: SecurityConfig,
) -> None:
    with (
        patch(
            "guard_core.sync.handlers.cloud_handler.fetch_aws_ip_ranges",
        ) as mock_aws,
        patch(
            "guard_core.sync.handlers.cloud_handler.fetch_gcp_ip_ranges",
            return_value={ipaddress.IPv4Network("172.16.0.0/12")},
        ),
        patch(
            "guard_core.sync.handlers.cloud_handler.fetch_azure_ip_ranges",
            return_value={ipaddress.IPv4Network("10.0.0.0/8")},
        ),
    ):
        mock_aws.return_value = {ipaddress.IPv4Network("192.168.0.0/24")}

        cloud_handler.redis_handler = None

        cloud_handler.refresh()
        assert cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})

        redis_handler = RedisManager(security_config_redis)
        redis_handler.initialize()
        cloud_handler.initialize_redis(redis_handler)

        with pytest.raises(RuntimeError) as exc_info:
            cloud_handler.refresh()
        assert "refresh_async()" in str(exc_info.value)

        redis_handler.close()


def test_cloud_ip_redis_error_handling(
    security_config_redis: SecurityConfig,
) -> None:
    with patch(
        "guard_core.sync.handlers.cloud_handler.fetch_aws_ip_ranges",
    ) as mock_aws:
        mock_aws.return_value = {ipaddress.IPv4Network("192.168.0.0/24")}

        redis_handler = RedisManager(security_config_redis)
        redis_handler.initialize()

        redis_handler.delete("cloud_ranges", "AWS")
        redis_handler.delete("guard:cloud_ip", "AWS")

        mock_aws.side_effect = Exception("API Error")
        cloud_handler.initialize_redis(redis_handler)

        cloud_handler.ip_ranges.pop("AWS", None)
        cloud_handler.refresh_async({"AWS"})

        assert isinstance(cloud_handler.ip_ranges["AWS"], set)
        assert len(cloud_handler.ip_ranges["AWS"]) == 0

        redis_handler.close()
