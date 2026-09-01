from guard_core.models import SecurityConfig


def test_on_block_defaults_to_none() -> None:
    assert SecurityConfig().on_block is None


def test_on_block_preserves_sync_callable() -> None:
    def hook(request: object, payload: dict) -> None:
        return None

    config = SecurityConfig(on_block=hook)

    assert config.on_block is hook


def test_on_block_preserves_async_callable() -> None:
    def hook(request: object, payload: dict) -> None:
        return None

    config = SecurityConfig(on_block=hook)

    assert config.on_block is hook
