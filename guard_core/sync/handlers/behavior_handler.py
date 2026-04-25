import json
import logging
import re
import time
from collections import defaultdict
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Literal

from guard_core.models import BehaviorRuleConfig, SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse


class BehaviorRule:
    def __init__(
        self,
        rule_type: Literal["usage", "return_pattern", "frequency"],
        threshold: int,
        window: int = 3600,
        pattern: str | None = None,
        action: Literal["ban", "log", "throttle", "alert"] = "log",
        custom_action: Callable | None = None,
        ban_duration: int | None = None,
        correlate_with_detection: bool = False,
    ):
        self.rule_type = rule_type
        self.threshold = threshold
        self.window = window
        self.pattern = pattern
        self.action = action
        self.custom_action = custom_action
        self.ban_duration = ban_duration
        self.correlate_with_detection = correlate_with_detection


class BehaviorTracker:
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.logger = logging.getLogger("guard_core.sync.handlers.behavior")
        self.usage_counts: dict[str, dict[str, list[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self.return_patterns: dict[str, dict[str, list[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self.redis_handler: Any | None = None
        self.agent_handler: Any | None = None

    def initialize_redis(self, redis_handler: Any) -> None:
        self.redis_handler = redis_handler

    def initialize_agent(self, agent_handler: Any) -> None:
        self.agent_handler = agent_handler

    def get_recent_event_count(self, ip: str, window_seconds: int) -> int:
        if not ip:
            return 0
        cutoff = time.time() - window_seconds
        count = 0
        for endpoint_bucket in self.usage_counts.values():
            for ts in endpoint_bucket.get(ip, []):
                if ts >= cutoff:
                    count += 1
        return count

    def track_endpoint_usage(
        self, endpoint_id: str, client_ip: str, rule: BehaviorRule
    ) -> bool:
        current_time = time.time()
        window_start = current_time - rule.window

        if self.redis_handler:
            key = f"behavior:usage:{endpoint_id}:{client_ip}"

            self.redis_handler.set_key(
                "behavior_usage", f"{key}:{current_time}", "1", ttl=rule.window
            )

            pattern = f"behavior_usage:{key}:*"
            keys = self.redis_handler.keys(pattern)

            valid_count = 0
            for key_name in keys:
                try:
                    timestamp = float(key_name.split(":")[-1])
                    if timestamp >= window_start:
                        valid_count += 1
                except (ValueError, IndexError):
                    continue

            return valid_count > rule.threshold

        timestamps = self.usage_counts[endpoint_id][client_ip]

        timestamps[:] = [ts for ts in timestamps if ts >= window_start]

        timestamps.append(current_time)

        return len(timestamps) > rule.threshold

    def track_return_pattern(
        self,
        endpoint_id: str,
        client_ip: str,
        response: GuardResponse,
        rule: BehaviorRule,
        effective_threshold: int | None = None,
    ) -> bool:
        if not rule.pattern:
            return False

        threshold = (
            effective_threshold if effective_threshold is not None else rule.threshold
        )
        current_time = time.time()
        window_start = current_time - rule.window

        pattern_matched = self._check_response_pattern(response, rule.pattern)

        if not pattern_matched:
            return False

        if self.redis_handler:
            key = f"behavior:return:{endpoint_id}:{client_ip}:{rule.pattern}"

            self.redis_handler.set_key(
                "behavior_returns", f"{key}:{current_time}", "1", ttl=rule.window
            )

            pattern_key = f"behavior_returns:{key}:*"
            keys = self.redis_handler.keys(pattern_key)

            valid_count = 0
            for key_name in keys:
                try:
                    timestamp = float(key_name.split(":")[-1])
                    if timestamp >= window_start:
                        valid_count += 1
                except (ValueError, IndexError):
                    continue

            return valid_count > threshold

        pattern_key = f"{endpoint_id}:{rule.pattern}"
        timestamps = self.return_patterns[pattern_key][client_ip]

        timestamps[:] = [ts for ts in timestamps if ts >= window_start]

        timestamps.append(current_time)

        return len(timestamps) > threshold

    def _check_response_pattern(self, response: GuardResponse, pattern: str) -> bool:
        try:
            if pattern.startswith("status:"):
                expected_status = int(pattern.split(":", 1)[1])
                return response.status_code == expected_status

            if hasattr(response, "body") and response.body:
                raw_body = response.body
                body_str = (
                    raw_body.decode("utf-8")
                    if isinstance(raw_body, bytes)
                    else str(raw_body)
                )

                if pattern.startswith("json:"):
                    json_pattern = pattern.split(":", 1)[1]
                    try:
                        response_json = json.loads(body_str)
                        return self._match_json_pattern(response_json, json_pattern)
                    except json.JSONDecodeError:
                        return False

                if pattern.startswith("regex:"):
                    regex_pattern = pattern.split(":", 1)[1]
                    return bool(re.search(regex_pattern, body_str, re.IGNORECASE))

                return pattern.lower() in body_str.lower()

            return False
        except Exception as e:
            self.logger.error(f"Error checking response pattern: {str(e)}")
            return False

    def _parse_pattern(self, pattern: str) -> tuple[str, str] | None:
        if "==" not in pattern:
            return None

        path, expected = pattern.split("==", 1)
        path = path.strip()
        expected = expected.strip().strip("\"'")
        return path, expected

    def _handle_array_match(self, current: Any, part: str, expected: str) -> bool:
        part = part[:-2]

        if not isinstance(current, dict) or part not in current:
            return False

        current = current[part]
        if not isinstance(current, list):
            return False

        return any(str(item).lower() == expected.lower() for item in current)

    def _traverse_json_path(self, data: Any, path: str) -> Any | None:
        current = data
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                return None
            current = current[part]
        return current

    def _match_json_pattern(self, data: Any, pattern: str) -> bool:
        try:
            parsed = self._parse_pattern(pattern)
            if not parsed:
                return False

            path, expected = parsed

            current = data
            for part in path.split("."):
                if part.endswith("[]"):
                    return self._handle_array_match(current, part, expected)

                if not isinstance(current, dict) or part not in current:
                    return False
                current = current[part]

            return str(current).lower() == expected.lower()

        except Exception:
            return False

    def _log_passive_mode_action(
        self, rule: BehaviorRule, client_ip: str, details: str
    ) -> None:
        prefix = "[PASSIVE MODE] "

        if rule.action == "ban":
            self.logger.warning(
                f"{prefix}Would ban IP {client_ip} for behavioral violation: {details}"
            )
        elif rule.action == "log":
            self.logger.warning(f"{prefix}Behavioral anomaly detected: {details}")
        elif rule.action == "throttle":
            self.logger.warning(f"{prefix}Would throttle IP {client_ip}: {details}")
        elif rule.action == "alert":
            self.logger.critical(f"{prefix}ALERT - Behavioral anomaly: {details}")

    def _execute_ban_action(
        self,
        client_ip: str,
        details: str,
        rule: "BehaviorRule | None" = None,
    ) -> None:
        from guard_core.sync.handlers.ipban_handler import ip_ban_manager

        duration = (
            rule.ban_duration
            if rule is not None and rule.ban_duration is not None
            else 3600
        )
        ip_ban_manager.ban_ip(client_ip, duration, "behavioral_violation")
        self.logger.warning(
            f"IP {client_ip} banned for behavioral violation: {details}"
        )

    def _execute_active_mode_action(
        self, rule: BehaviorRule, client_ip: str, endpoint_id: str, details: str
    ) -> None:
        if rule.custom_action:
            rule.custom_action(client_ip, endpoint_id, details)
            return

        if rule.action == "ban":
            self._execute_ban_action(client_ip, details, rule)
        elif rule.action == "log":
            self.logger.warning(f"Behavioral anomaly detected: {details}")
        elif rule.action == "throttle":
            self.logger.warning(f"Throttling IP {client_ip}: {details}")
        elif rule.action == "alert":
            self.logger.critical(f"ALERT - Behavioral anomaly: {details}")

    def apply_action(
        self, rule: BehaviorRule, client_ip: str, endpoint_id: str, details: str
    ) -> None:
        if self.agent_handler:
            self._send_behavior_event(
                event_type="behavioral_violation",
                ip_address=client_ip,
                action_taken=rule.action
                if not self.config.passive_mode
                else "logged_only",
                reason=f"Behavioral rule violated: {details}",
                endpoint=endpoint_id,
                rule_type=rule.rule_type,
                threshold=rule.threshold,
                window=rule.window,
            )

        if self.config.passive_mode:
            self._log_passive_mode_action(rule, client_ip, details)
        else:
            self._execute_active_mode_action(rule, client_ip, endpoint_id, details)

    def _send_behavior_event(
        self,
        event_type: str,
        ip_address: str,
        action_taken: str,
        reason: str,
        **kwargs: Any,
    ) -> None:
        if not self.agent_handler:
            return

        try:
            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=event_type,
                ip_address=ip_address,
                action_taken=action_taken,
                reason=reason,
                metadata=kwargs,
            )
            self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send behavior event to agent: {e}")


def config_to_rule(cfg: BehaviorRuleConfig) -> BehaviorRule:
    return BehaviorRule(
        rule_type=cfg.rule_type,
        threshold=cfg.threshold,
        window=cfg.window,
        pattern=cfg.pattern,
        action=cfg.action,
        ban_duration=cfg.ban_duration,
        correlate_with_detection=cfg.correlate_with_detection,
    )
