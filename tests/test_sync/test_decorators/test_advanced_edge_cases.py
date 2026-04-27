from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.decorators import SecurityDecorator


@pytest.fixture
def adv_security_config() -> SecurityConfig:
    return SecurityConfig()


@pytest.fixture
def decorator(adv_security_config: SecurityConfig) -> SecurityDecorator:
    return SecurityDecorator(adv_security_config)


def test_honeypot_form_exception_caught(
    decorator: SecurityDecorator,
) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["trap_field"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = decorated_func._guard_route_id
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    from tests.test_sync.conftest import SyncMockGuardRequest

    mock_request = SyncMockGuardRequest(
        method="POST",
        headers={"content-type": "application/x-www-form-urlencoded"},
        body_content=b"\xff\xfe invalid utf8",
    )

    result = validator(mock_request)
    assert result is None


def test_honeypot_non_post_method(decorator: SecurityDecorator) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["trap_field"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = decorated_func._guard_route_id
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    mock_request = MagicMock()
    mock_request.method = "GET"

    result = validator(mock_request)
    assert result is None

    mock_request.method = "DELETE"
    result = validator(mock_request)
    assert result is None


def test_honeypot_unsupported_content_type(
    decorator: SecurityDecorator,
) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["trap_field"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = decorated_func._guard_route_id
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    mock_request = MagicMock()
    mock_request.method = "POST"
    mock_request.headers.get = lambda key, default="": (
        "text/plain" if key == "content-type" else default
    )

    result = validator(mock_request)
    assert result is None

    mock_request.headers.get = lambda key, default="": (
        "multipart/form-data" if key == "content-type" else default
    )

    result = validator(mock_request)
    assert result is None


@pytest.mark.parametrize(
    "method",
    ["GET", "DELETE", "OPTIONS", "HEAD"],
)
def test_honeypot_various_non_modifying_methods(
    decorator: SecurityDecorator, method: str
) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["trap_field"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = decorated_func._guard_route_id
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    mock_request = MagicMock()
    mock_request.method = method

    result = validator(mock_request)
    assert result is None


@pytest.mark.parametrize(
    "method",
    ["POST", "PUT", "PATCH"],
)
def test_honeypot_modifying_methods_without_content_type(
    decorator: SecurityDecorator, method: str
) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["trap_field"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = decorated_func._guard_route_id
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    mock_request = MagicMock()
    mock_request.method = method
    mock_request.headers.get = lambda key, default="": (
        "application/xml" if key == "content-type" else default
    )

    result = validator(mock_request)
    assert result is None
