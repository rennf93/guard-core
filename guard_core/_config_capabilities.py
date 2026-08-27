import importlib.util
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig


def _extra_installed(*module_names: str) -> bool:
    return any(importlib.util.find_spec(name) is not None for name in module_names)


def cloud_blocking_enabled(config: "SecurityConfig") -> bool:
    return bool(config.block_cloud_providers) or config.enable_dynamic_rules
