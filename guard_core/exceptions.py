class GuardCoreError(Exception):
    pass


class GuardRedisError(GuardCoreError):
    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


class AgentPackageNotInstalledError(GuardCoreError):
    pass
