import logging
import threading
import time
from collections.abc import Callable, Sized
from typing import cast

from guard_core.exceptions import GuardRedisError
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


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
        self._rebuild_lock = threading.Lock()
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

    def _is_stale(self, config: SecurityConfig) -> bool:
        if config.revision != self._built_revision:
            return True
        return self._container_signature(config) != self._built_signature

    def _rebuild_if_stale(self) -> None:
        config = self._config
        if config is None or self._rebuild_checks is None:
            return
        if not self._is_stale(config):
            return
        revision = config.revision
        signature = self._container_signature(config)
        muted_check_logs = config.muted_check_logs
        checks = self._rebuild_checks()
        with self._rebuild_lock:
            self.checks = checks
            self.muted_check_logs = muted_check_logs
            self._built_revision = revision
            self._built_signature = signature

    def _log_extra(self, check: SecurityCheck, request: SyncGuardRequest) -> dict:
        return {
            "check": check.check_name,
            "path": request.url_path,
            "method": request.method,
        }

    def _handle_check_error(
        self, check: SecurityCheck, request: SyncGuardRequest, error: Exception
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
            return check.create_error_response(
                status_code=500,
                default_message="Security check failed",
            )

        return None

    def _handle_rebuild_error(
        self, request: SyncGuardRequest, error: Exception
    ) -> GuardResponse | None:
        self.logger.error(
            f"Error rebuilding security checks: {error}",
            extra={"path": request.url_path, "method": request.method},
            exc_info=True,
        )
        config = cast(SecurityConfig, self._config)
        if not config.fail_secure:
            return None
        if not self.checks:
            raise error
        self.logger.warning("Blocking request due to rebuild error in fail-secure mode")
        return self.checks[0].create_error_response(
            status_code=500,
            default_message="Security check failed",
        )

    def execute(self, request: SyncGuardRequest) -> GuardResponse | None:
        try:
            self._rebuild_if_stale()
        except Exception as e:
            response = self._handle_rebuild_error(request, e)
            if response is not None:
                return response

        request.state._guard_pipeline_start = time.monotonic()

        for check in self.checks:
            try:
                response = check.check(request)
                if response is not None:
                    if check.check_name not in self.muted_check_logs:
                        self.logger.info(
                            f"Request blocked by {check.check_name}",
                            extra=self._log_extra(check, request),
                        )
                    return response

            except Exception as e:
                error_response = self._handle_check_error(check, request, e)
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
