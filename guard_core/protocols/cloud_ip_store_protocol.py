from typing import Protocol, runtime_checkable


@runtime_checkable
class CloudIpStoreProtocol(Protocol):
    async def get(self, provider: str) -> set[str] | None: ...

    async def set(
        self, provider: str, ranges: set[str], ttl: int | None = None
    ) -> None: ...

    async def clear(self) -> None: ...
