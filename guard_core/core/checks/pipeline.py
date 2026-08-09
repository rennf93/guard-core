import logging
import time
from collections.abc import Callable, Sized

from guard_core.core.checks.base import SecurityCheck
from guard_core.exceptions import GuardRedisError
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse


class SecurityCheckPipeline:
    def __init__(
        self,
        checks: list[SecurityCheck],
        muted_check_logs: set[str] | None = None,
        *,
        config: SecurityConfig | None = None,
        rebuild_checks: Callable[[], list[SecurityCheck]] | None = None,
        watched_container_fields: tuple[str, ...] | None = None,
    ) -> None:
        self.checks = checks
        self.muted_check_logs = muted_check_logs or set()
        self.logger = logging.getLogger(__name__)
        self._config = config
        self._rebuild_checks = rebuild_checks
        self._watched_container_fields = watched_container_fields or ()
        self._built_revision = config.revision if config is not None else None
        self._built_signature = (
            self._container_signature(config) if config is not None else ()
        )

    @staticmethod
    def _container_size(value: Sized | None) -> int:
        return 0 if value is None else len(value)

    def _container_signature(self, config: SecurityConfig) -> tuple[int, ...]:
        return tuple(
            self._container_size(getattr(config, field))
            for field in self._watched_container_fields
        )

    def _rebuild_if_stale(self) -> None:
        config = self._config
        if config is None or self._rebuild_checks is None:
            return
        if config.revision == self._built_revision:
            if self._container_signature(config) == self._built_signature:
                return
        self.checks = self._rebuild_checks()
        self.muted_check_logs = config.muted_check_logs
        self._built_revision = config.revision
        self._built_signature = self._container_signature(config)

    def _log_extra(self, check: SecurityCheck, request: GuardRequest) -> dict:
        return {
            "check": check.check_name,
            "path": request.url_path,
            "method": request.method,
        }

    async def _handle_check_error(
        self, check: SecurityCheck, request: GuardRequest, error: Exception
    ) -> GuardResponse | None:
        muted = check.check_name in self.muted_check_logs

        if isinstance(error, GuardRedisError) and check.config.redis_fail_open:
            if not muted:
                self.logger.warning(
                    f"Skipping check {check.check_name}: Redis "
                    f"unavailable, failing open (redis_fail_open=True)",
                    extra=self._log_extra(check, request),
                )
            return None

        if not muted:
            self.logger.error(
                f"Error in security check {check.check_name}: {error}",
                extra=self._log_extra(check, request),
                exc_info=True,
            )

        if check.config.fail_secure:
            if not muted:
                self.logger.warning(
                    f"Blocking request due to check error "
                    f"in fail-secure mode: {check.check_name}"
                )
            return await check.create_error_response(
                status_code=500,
                default_message="Security check failed",
            )

        return None

    async def execute(self, request: GuardRequest) -> GuardResponse | None:
        self._rebuild_if_stale()
        request.state._guard_pipeline_start = time.monotonic()

        for check in self.checks:
            try:
                response = await check.check(request)
                if response is not None:
                    if check.check_name not in self.muted_check_logs:
                        self.logger.info(
                            f"Request blocked by {check.check_name}",
                            extra=self._log_extra(check, request),
                        )
                    return response

            except Exception as e:
                error_response = await self._handle_check_error(check, request, e)
                if error_response is not None:
                    return error_response

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
