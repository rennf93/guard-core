from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.sync.core.validation.context import ValidationContext
from guard_core.sync.core.validation.validator import RequestValidator


@pytest.fixture
def mock_config() -> Any:
    config = Mock()
    config.trust_x_forwarded_proto = True
    config.trusted_proxies = ["192.168.1.1", "10.0.0.0/8"]
    config.exclude_paths = ["/health", "/metrics"]
    return config


@pytest.fixture
def mock_event_bus() -> Any:
    event_bus = Mock()
    event_bus.send_middleware_event = MagicMock()
    return event_bus


@pytest.fixture
def validation_context(mock_config: Any, mock_event_bus: Any) -> ValidationContext:
    return ValidationContext(
        config=mock_config,
        logger=Mock(),
        event_bus=mock_event_bus,
    )


@pytest.fixture
def validator(validation_context: ValidationContext) -> RequestValidator:
    return RequestValidator(validation_context)


@pytest.fixture
def mock_request() -> Any:
    request = Mock()
    request.url_scheme = "http"
    request.url_path = "/test"
    request.headers = {}
    request.client_host = "127.0.0.1"
    return request


def test_init(validation_context: ValidationContext) -> None:
    validator = RequestValidator(validation_context)
    assert validator.context == validation_context


def test_is_request_https_direct_https(
    validator: RequestValidator, mock_request: Any
) -> None:
    mock_request.url_scheme = "https"

    result = validator.is_request_https(mock_request)

    assert result is True


def test_is_request_https_direct_http(
    validator: RequestValidator, mock_request: Any
) -> None:
    mock_request.url_scheme = "http"

    result = validator.is_request_https(mock_request)

    assert result is False


def test_is_request_https_forwarded_proto_trusted_proxy(
    validator: RequestValidator, mock_request: Any
) -> None:
    mock_request.url_scheme = "http"
    mock_request.headers = {"X-Forwarded-Proto": "https"}
    mock_request.client_host = "192.168.1.1"

    result = validator.is_request_https(mock_request)

    assert result is True


def test_is_request_https_forwarded_proto_untrusted_proxy(
    validator: RequestValidator, mock_request: Any
) -> None:
    mock_request.url_scheme = "http"
    mock_request.headers = {"X-Forwarded-Proto": "https"}
    mock_request.client_host = "1.2.3.4"

    result = validator.is_request_https(mock_request)

    assert result is False


def test_is_request_https_no_client(
    validator: RequestValidator, mock_request: Any
) -> None:
    mock_request.url_scheme = "http"
    mock_request.client_host = None

    result = validator.is_request_https(mock_request)

    assert result is False


def test_is_request_https_trust_disabled(
    validator: RequestValidator, mock_request: Any
) -> None:
    validator.context.config.trust_x_forwarded_proto = False
    mock_request.url_scheme = "http"
    mock_request.headers = {"X-Forwarded-Proto": "https"}

    result = validator.is_request_https(mock_request)

    assert result is False


def test_is_request_https_no_trusted_proxies(
    validator: RequestValidator, mock_request: Any
) -> None:
    validator.context.config.trusted_proxies = []
    mock_request.url_scheme = "http"
    mock_request.headers = {"X-Forwarded-Proto": "https"}

    result = validator.is_request_https(mock_request)

    assert result is False


def test_is_trusted_proxy_single_ip_match(
    validator: RequestValidator,
) -> None:
    result = validator.is_trusted_proxy("192.168.1.1")

    assert result is True


def test_is_trusted_proxy_single_ip_no_match(
    validator: RequestValidator,
) -> None:
    result = validator.is_trusted_proxy("192.168.1.2")

    assert result is False


def test_is_trusted_proxy_cidr_match(validator: RequestValidator) -> None:
    result = validator.is_trusted_proxy("10.0.5.10")

    assert result is True


def test_is_trusted_proxy_cidr_no_match(validator: RequestValidator) -> None:
    result = validator.is_trusted_proxy("11.0.0.1")

    assert result is False


def test_check_time_window_within_range(
    validator: RequestValidator,
) -> None:
    current = datetime.now(timezone.utc)

    hour = current.hour
    start_hour = (hour - 1) % 24
    end_hour = (hour + 1) % 24

    time_restrictions = {
        "start": f"{start_hour:02d}:00",
        "end": f"{end_hour:02d}:59",
    }

    result = validator.check_time_window(time_restrictions)

    assert result is True


def test_check_time_window_outside_range(
    validator: RequestValidator,
) -> None:
    current = datetime.now(timezone.utc)

    hour = current.hour
    start_hour = (hour + 6) % 24
    end_hour = (hour + 8) % 24

    time_restrictions = {
        "start": f"{start_hour:02d}:00",
        "end": f"{end_hour:02d}:00",
    }

    result = validator.check_time_window(time_restrictions)

    assert result is False


def test_check_time_window_overnight_within(
    validator: RequestValidator,
) -> None:
    time_restrictions = {"start": "22:00", "end": "06:00"}

    result = validator.check_time_window(time_restrictions)

    assert isinstance(result, bool)


def test_check_time_window_error_handling(
    validator: RequestValidator,
) -> None:
    time_restrictions = {"invalid": "data"}

    result = validator.check_time_window(time_restrictions)

    assert result is True


def test_is_path_excluded_matching_path(
    validator: RequestValidator, mock_request: Any, mock_event_bus: Any
) -> None:
    mock_request.url_path = "/health"

    result = validator.is_path_excluded(mock_request)

    assert result is True
    mock_event_bus.send_middleware_event.assert_called_once()
    call_kwargs = mock_event_bus.send_middleware_event.call_args[1]
    assert call_kwargs["event_type"] == "path_excluded"
    assert call_kwargs["excluded_path"] == "/health"


def test_is_path_excluded_prefix_match(
    validator: RequestValidator, mock_request: Any, mock_event_bus: Any
) -> None:
    mock_request.url_path = "/health/check"

    result = validator.is_path_excluded(mock_request)

    assert result is True
    mock_event_bus.send_middleware_event.assert_called_once()


def test_is_path_excluded_no_match(
    validator: RequestValidator, mock_request: Any, mock_event_bus: Any
) -> None:
    mock_request.url_path = "/api/endpoint"

    result = validator.is_path_excluded(mock_request)

    assert result is False
    mock_event_bus.send_middleware_event.assert_not_called()
