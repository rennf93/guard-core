import pytest

pytestmark = pytest.mark.skip(reason="SecurityMiddleware not available in guard-core")
