import logging
import time

from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


class SecurityCheckPipeline:
    def __init__(
        self,
        checks: list[SecurityCheck],
        muted_check_logs: set[str] | None = None,
    ) -> None:
        self.checks = checks
        self.muted_check_logs = muted_check_logs or set()
        self.logger = logging.getLogger(__name__)

    def execute(self, request: SyncGuardRequest) -> GuardResponse | None:
        request.state._guard_pipeline_start = time.monotonic()

        for check in self.checks:
            try:
                response = check.check(request)
                if response is not None:
                    if check.check_name not in self.muted_check_logs:
                        self.logger.info(
                            f"Request blocked by {check.check_name}",
                            extra={
                                "check": check.check_name,
                                "path": request.url_path,
                                "method": request.method,
                            },
                        )
                    return response

            except Exception as e:
                if check.check_name not in self.muted_check_logs:
                    self.logger.error(
                        f"Error in security check {check.check_name}: {e}",
                        extra={
                            "check": check.check_name,
                            "path": request.url_path,
                            "method": request.method,
                        },
                        exc_info=True,
                    )

                if hasattr(check.config, "fail_secure") and check.config.fail_secure:
                    if check.check_name not in self.muted_check_logs:
                        self.logger.warning(
                            f"Blocking request due to check error "
                            f"in fail-secure mode: {check.check_name}"
                        )
                    return check.create_error_response(
                        status_code=500,
                        default_message="Security check failed",
                    )

                continue

        return None

    def add_check(self, check: SecurityCheck) -> None:
        self.checks.append(check)

    def insert_check(self, index: int, check: SecurityCheck) -> None:
        self.checks.insert(index, check)

    def remove_check(self, check_name: str) -> bool:
        for i, check in enumerate(self.checks):
            if check.check_name == check_name:
                self.checks.pop(i)
                return True
        return False

    def get_check_names(self) -> list[str]:
        return [check.check_name for check in self.checks]

    def __len__(self) -> int:
        return len(self.checks)

    def __repr__(self) -> str:
        check_names = ", ".join(self.get_check_names())
        return f"SecurityCheckPipeline({len(self.checks)} checks: {check_names})"
