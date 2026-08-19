import ipaddress
import logging
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Optional

from redis.exceptions import NoScriptError, RedisError

from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.scripts.rate_lua import RATE_LIMIT_SCRIPT
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import log_activity

_by_ip_logger = logging.getLogger("guard_core.sync.handlers.ratelimit")
_by_ip_request_timestamps: defaultdict[str, deque[float]] = defaultdict(deque)
_by_ip_lock = threading.Lock()


def _redis_request_count(
    redis_handler: Any,
    logger: logging.Logger,
    client_ip: str,
    current_time: float,
    window_start: float,
    rate_limit_window: int,
    rate_limit: int,
    rate_limit_script_sha: str | None,
    on_script_reloaded: Callable[[], None] | None = None,
    endpoint_path: str = "",
) -> tuple[int | None, str | None]:
    if not redis_handler:
        return None, rate_limit_script_sha

    rate_key = (
        f"rate:{client_ip}:{endpoint_path}" if endpoint_path else f"rate:{client_ip}"
    )
    key_name = f"{redis_handler.config.redis_prefix}rate_limit:{rate_key}"

    try:
        if rate_limit_script_sha:
            with redis_handler.get_connection() as conn:
                try:
                    count = conn.evalsha(
                        rate_limit_script_sha,
                        1,
                        key_name,
                        current_time,
                        rate_limit_window,
                        rate_limit,
                    )
                except NoScriptError:
                    rate_limit_script_sha = conn.script_load(RATE_LIMIT_SCRIPT)
                    logger.info("Rate limit Lua script reloaded after NOSCRIPT")
                    if on_script_reloaded is not None:
                        on_script_reloaded()
                    count = conn.evalsha(
                        rate_limit_script_sha,
                        1,
                        key_name,
                        current_time,
                        rate_limit_window,
                        rate_limit,
                    )
            return int(count), rate_limit_script_sha
        else:
            with redis_handler.get_connection() as conn:
                pipeline = conn.pipeline()
                pipeline.zadd(key_name, {str(current_time): current_time})
                pipeline.zremrangebyscore(key_name, 0, window_start)
                pipeline.zcard(key_name)
                pipeline.expire(key_name, rate_limit_window * 2)
                results = pipeline.execute()
                return int(results[2]), rate_limit_script_sha

    except RedisError as e:
        logger.error(f"Redis rate limiting error: {str(e)}")
        logger.info("Falling back to in-memory rate limiting")
    except Exception as e:
        logger.error(f"Unexpected error in rate limiting: {str(e)}")

    return None, rate_limit_script_sha


def _in_memory_request_count(
    request_timestamps: defaultdict[str, deque[float]],
    lock: threading.Lock,
    client_ip: str,
    window_start: float,
    current_time: float,
    endpoint_path: str = "",
) -> int:
    key = f"{client_ip}:{endpoint_path}" if endpoint_path else client_ip

    with lock:
        while request_timestamps[key] and request_timestamps[key][0] <= window_start:
            request_timestamps[key].popleft()

        request_count = len(request_timestamps[key])
        request_timestamps[key].append(current_time)

    return request_count


def check_rate_limit_by_ip(
    ip: str,
    config: SecurityConfig,
    redis_handler: Any = None,
    endpoint_path: str = "",
) -> bool:
    """Check and record a rate-limit hit for a raw IP, outside the HTTP pipeline.

    Returns True when the call is allowed (under limit), False when rate-limited.
    Every call records a hit in the sliding window, exactly like the pipeline path,
    so calling this to "just check" also consumes one slot of the budget. Does not
    construct or mutate the ``RateLimitManager`` singleton: it calls the same
    module-level counting functions the pipeline uses, against a store dedicated
    to this primitive. With ``endpoint_path=""`` (the default) the Redis key
    collapses to ``{prefix}rate_limit:rate:{ip}``, the same bucket the HTTP
    pipeline's global rate limit uses for that IP, so the two share one budget by
    design. Pass a non-empty ``endpoint_path`` (e.g. "ws") for an isolated budget,
    keyed apart from that default bucket: isolation is guaranteed by the input
    validation below, since ``ip`` must parse as a canonical IP address and
    ``endpoint_path`` can never itself contain a ``:``, the joined key can never
    collide with a different endpoint_path's bucket. The in-memory fallback is
    process-local and never shares counts with the pipeline singleton's own
    in-memory store, Redis-backed deployments do.

    Raises:
        ValueError: if ``ip`` does not parse via ``ipaddress.ip_address``, or if
            ``endpoint_path`` contains a ``:``. Validation runs before any
            counting side effect and before the ``enable_rate_limiting`` early
            return, so rejected input never records a hit.
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError(f"check_rate_limit_by_ip: invalid ip {ip!r}") from exc
    if ":" in endpoint_path:
        raise ValueError(
            f"check_rate_limit_by_ip: endpoint_path must not contain ':' "
            f"(got {endpoint_path!r})"
        )

    if not config.enable_rate_limiting:
        return True

    current_time = time.time()
    window_start = current_time - config.rate_limit_window

    if config.enable_redis and redis_handler:
        count, _ = _redis_request_count(
            redis_handler,
            _by_ip_logger,
            ip,
            current_time,
            window_start,
            config.rate_limit_window,
            config.rate_limit,
            None,
            None,
            endpoint_path,
        )
        if count is not None:
            return count <= config.rate_limit

    request_count = _in_memory_request_count(
        _by_ip_request_timestamps,
        _by_ip_lock,
        ip,
        window_start,
        current_time,
        endpoint_path=endpoint_path,
    )
    return request_count < config.rate_limit


class RateLimitManager:
    _instance: Optional["RateLimitManager"] = None
    _lock: threading.Lock
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
            cls._instance._lock = threading.Lock()

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

    def _emit_script_reloaded_event(self) -> None:
        if not self.agent_handler:
            return
        try:
            from guard_core._pydantic_plugin_mute import get_telemetry_model

            SecurityEvent = get_telemetry_model("SecurityEvent")

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="rate_limit_script_reloaded",
                ip_address="system",
                action_taken="script_reloaded",
                reason="NOSCRIPT recovery: Lua script re-cached on Redis",
            )
            self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send script-reload event: {e}")

    def _get_redis_request_count(
        self,
        client_ip: str,
        current_time: float,
        window_start: float,
        endpoint_path: str = "",
        rate_limit_window: int | None = None,
        rate_limit: int | None = None,
    ) -> int | None:
        count, self.rate_limit_script_sha = _redis_request_count(
            self.redis_handler,
            self.logger,
            client_ip,
            current_time,
            window_start,
            rate_limit_window or self.config.rate_limit_window,
            rate_limit if rate_limit is not None else self.config.rate_limit,
            self.rate_limit_script_sha,
            self._emit_script_reloaded_event,
            endpoint_path,
        )
        return count

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
        return _in_memory_request_count(
            self.request_timestamps,
            self._lock,
            client_ip,
            window_start,
            current_time,
            endpoint_path=endpoint_path,
        )

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

            from guard_core._pydantic_plugin_mute import get_telemetry_model
            from guard_core.sync.utils import get_pipeline_response_time

            SecurityEvent = get_telemetry_model("SecurityEvent")

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="rate_limited",
                ip_address=client_ip,
                action_taken="request_blocked",
                reason=f"{message}: {details}",
                endpoint=str(request.url_path),
                method=request.method,
                response_time=get_pipeline_response_time(request),
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
