import logging
import time
from collections import defaultdict, deque
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Optional

from redis.exceptions import RedisError

from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.scripts.rate_lua import RATE_LIMIT_SCRIPT
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import log_activity


class RateLimitManager:
    _instance: Optional["RateLimitManager"] = None
    config: SecurityConfig
    request_timestamps: defaultdict[str, deque[float]]
    logger: logging.Logger
    redis_handler: Any = None
    agent_handler: Any = None
    rate_limit_script_sha: str | None = None

    def __new__(
        cls: type["RateLimitManager"], config: SecurityConfig
    ) -> "RateLimitManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.config = config
            cls._instance.request_timestamps = defaultdict(deque)
            cls._instance.logger = logging.getLogger(
                "guard_core.sync.handlers.ratelimit"
            )
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None
            cls._instance.rate_limit_script_sha = None

        cls._instance.config = config
        return cls._instance

    def initialize_redis(self, redis_handler: Any) -> None:
        self.redis_handler = redis_handler

        if self.redis_handler and self.config.enable_redis:
            try:
                with self.redis_handler.get_connection() as conn:
                    self.rate_limit_script_sha = conn.script_load(RATE_LIMIT_SCRIPT)
                    self.logger.info("Rate limiting Lua script loaded successfully")
            except Exception as e:
                self.logger.error(f"Failed to load rate limiting Lua script: {str(e)}")

    def initialize_agent(self, agent_handler: Any) -> None:
        self.agent_handler = agent_handler

    def _get_redis_request_count(
        self,
        client_ip: str,
        current_time: float,
        window_start: float,
        endpoint_path: str = "",
        rate_limit_window: int | None = None,
        rate_limit: int | None = None,
    ) -> int | None:
        if not self.redis_handler:
            return None

        rate_key = (
            f"rate:{client_ip}:{endpoint_path}"
            if endpoint_path
            else f"rate:{client_ip}"
        )
        key_name = f"{self.redis_handler.config.redis_prefix}rate_limit:{rate_key}"
        window = rate_limit_window or self.config.rate_limit_window
        limit = rate_limit if rate_limit is not None else self.config.rate_limit

        try:
            if self.rate_limit_script_sha:
                with self.redis_handler.get_connection() as conn:
                    count = conn.evalsha(
                        self.rate_limit_script_sha,
                        1,
                        key_name,
                        current_time,
                        window,
                        limit,
                    )
                return int(count)
            else:
                with self.redis_handler.get_connection() as conn:
                    pipeline = conn.pipeline()
                    pipeline.zadd(key_name, {str(current_time): current_time})
                    pipeline.zremrangebyscore(key_name, 0, window_start)
                    pipeline.zcard(key_name)
                    pipeline.expire(key_name, window * 2)
                    results = pipeline.execute()
                    return int(results[2])

        except RedisError as e:
            self.logger.error(f"Redis rate limiting error: {str(e)}")
            self.logger.info("Falling back to in-memory rate limiting")
        except Exception as e:
            self.logger.error(f"Unexpected error in rate limiting: {str(e)}")

        return None

    def _handle_rate_limit_exceeded(
        self,
        request: SyncGuardRequest,
        client_ip: str,
        count: int,
        create_error_response: Callable[[int, str], GuardResponse],
        rate_limit_window: int | None = None,
    ) -> GuardResponse:
        window = rate_limit_window or self.config.rate_limit_window
        message = "Rate limit exceeded for IP:"
        detail = f"requests in {window}s window)"
        log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"{message} {client_ip} ({count} {detail}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        if self.agent_handler:
            self._send_rate_limit_event(request, client_ip, count)

        return create_error_response(
            429,
            "Too many requests",
        )

    def _get_in_memory_request_count(
        self,
        client_ip: str,
        window_start: float,
        current_time: float,
        endpoint_path: str = "",
    ) -> int:
        key = f"{client_ip}:{endpoint_path}" if endpoint_path else client_ip

        while (
            self.request_timestamps[key]
            and self.request_timestamps[key][0] <= window_start
        ):
            self.request_timestamps[key].popleft()

        request_count = len(self.request_timestamps[key])
        self.request_timestamps[key].append(current_time)

        return request_count

    def check_rate_limit(
        self,
        request: SyncGuardRequest,
        client_ip: str,
        create_error_response: Callable[[int, str], GuardResponse],
        endpoint_path: str = "",
        rate_limit: int | None = None,
        rate_limit_window: int | None = None,
    ) -> GuardResponse | None:
        if not self.config.enable_rate_limiting:
            return None

        effective_limit = (
            rate_limit if rate_limit is not None else self.config.rate_limit
        )
        effective_window = (
            rate_limit_window
            if rate_limit_window is not None
            else self.config.rate_limit_window
        )

        current_time = time.time()
        window_start = current_time - effective_window

        if self.config.enable_redis and self.redis_handler:
            count = self._get_redis_request_count(
                client_ip,
                current_time,
                window_start,
                endpoint_path=endpoint_path,
                rate_limit_window=effective_window,
                rate_limit=effective_limit,
            )

            if count is not None:
                if count > effective_limit:
                    return self._handle_rate_limit_exceeded(
                        request,
                        client_ip,
                        count,
                        create_error_response,
                        rate_limit_window=effective_window,
                    )
                return None

        request_count = self._get_in_memory_request_count(
            client_ip, window_start, current_time, endpoint_path=endpoint_path
        )

        if request_count >= effective_limit:
            return self._handle_rate_limit_exceeded(
                request,
                client_ip,
                request_count + 1,
                create_error_response,
                rate_limit_window=effective_window,
            )

        return None

    def _send_rate_limit_event(
        self, request: SyncGuardRequest, client_ip: str, request_count: int
    ) -> None:
        try:
            message = "Rate limit exceeded"
            details = (
                f"{request_count} requests in {self.config.rate_limit_window}s window"
            )

            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="rate_limited",
                ip_address=client_ip,
                action_taken="request_blocked",
                reason=f"{message}: {details}",
                endpoint=str(request.url_path),
                method=request.method,
                metadata={
                    "request_count": request_count,
                    "rate_limit": self.config.rate_limit,
                    "window": self.config.rate_limit_window,
                },
            )
            self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send rate limit event to agent: {e}")

    def reset(self) -> None:
        self.request_timestamps.clear()

        if self.config.enable_redis and self.redis_handler:
            try:
                keys = self.redis_handler.keys("rate_limit:rate:*")
                if keys and len(keys) > 0:
                    self.redis_handler.delete_pattern("rate_limit:rate:*")
            except Exception as e:
                self.logger.error(f"Failed to reset Redis rate limits: {str(e)}")


rate_limit_handler = RateLimitManager
