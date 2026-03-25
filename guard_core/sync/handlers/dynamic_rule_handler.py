import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any

from guard_core.models import DynamicRules, SecurityConfig


class DynamicRuleManager:
    _instance = None
    config: SecurityConfig
    agent_handler: Any = None
    redis_handler: Any = None
    logger: logging.Logger
    last_update: float = 0
    current_rules: DynamicRules | None = None
    update_task: threading.Thread | None = None

    def __new__(
        cls: type["DynamicRuleManager"], config: SecurityConfig
    ) -> "DynamicRuleManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.config = config
            cls._instance.logger = logging.getLogger(
                "guard_core.sync.handlers.dynamic_rule"
            )
            cls._instance.last_update = 0
            cls._instance.current_rules = None
            cls._instance.update_task = None
        return cls._instance

    def initialize_agent(self, agent_handler: Any) -> None:
        self.agent_handler = agent_handler

        if self.config.enable_dynamic_rules and not self.update_task:
            self.update_task = threading.Thread(
                target=self._rule_update_loop, daemon=True
            )
            self.update_task.start()
            self.logger.info("Started dynamic rule update loop")

    def initialize_redis(self, redis_handler: Any) -> None:
        self.redis_handler = redis_handler

    def _rule_update_loop(self) -> None:
        while True:
            try:
                self.update_rules()
                time.sleep(self.config.dynamic_rule_interval)
            except Exception as e:
                self.logger.error(f"Error in dynamic rule update loop: {e}")
                time.sleep(min(60, self.config.dynamic_rule_interval))

    def _should_update_rules(self, rules: DynamicRules) -> bool:
        if not self.current_rules:
            return True

        return not (
            rules.rule_id == self.current_rules.rule_id
            and rules.version <= self.current_rules.version
        )

    def _send_rule_received_event(self, rules: DynamicRules) -> None:
        if not self.agent_handler:
            return

        try:
            from guard_agent import SecurityEvent

            reason = f"Received updated rules {rules.rule_id} v{rules.version}"

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="dynamic_rule_updated",
                ip_address="system",
                action_taken="rules_received",
                reason=reason,
                metadata={
                    "rule_id": rules.rule_id,
                    "version": rules.version,
                    "previous_version": self.current_rules.version
                    if self.current_rules
                    else 0,
                },
            )
            self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send rule updated event: {e}")

    def update_rules(self) -> None:
        if not self.config.enable_dynamic_rules or not self.agent_handler:
            return

        try:
            rules = self.agent_handler.get_dynamic_rules()
            if not rules:
                return

            if not self._should_update_rules(rules):
                return

            self._send_rule_received_event(rules)

            self.logger.info(
                f"Applying dynamic rules: {rules.rule_id} v{rules.version}"
            )
            self._apply_rules(rules)

            self.current_rules = rules
            self.last_update = time.time()

            self._send_rule_applied_event(rules)

        except Exception as e:
            self.logger.error(f"Failed to update dynamic rules: {e}")

    def _apply_ip_rules(self, rules: DynamicRules) -> None:
        if rules.ip_blacklist:
            self._apply_ip_bans(rules.ip_blacklist, rules.ip_ban_duration)

        if rules.ip_whitelist:
            self._apply_ip_whitelist(rules.ip_whitelist)

    def _apply_blocking_rules(self, rules: DynamicRules) -> None:
        if rules.blocked_countries or rules.whitelist_countries:
            self._apply_country_rules(
                rules.blocked_countries, rules.whitelist_countries
            )

        if rules.blocked_cloud_providers:
            self._apply_cloud_provider_rules(rules.blocked_cloud_providers)

        if rules.blocked_user_agents:
            self._apply_user_agent_rules(rules.blocked_user_agents)

        if rules.suspicious_patterns:
            self._apply_pattern_rules(rules.suspicious_patterns)

    def _apply_rules(self, rules: DynamicRules) -> None:
        try:
            self._apply_ip_rules(rules)

            self._apply_blocking_rules(rules)

            if rules.global_rate_limit or rules.endpoint_rate_limits:
                self._apply_rate_limit_rules(rules)

            self._apply_feature_toggles(rules)

            if rules.emergency_mode:
                self._activate_emergency_mode(rules.emergency_whitelist)

        except Exception as e:
            self.logger.error(f"Failed to apply dynamic rules: {e}")
            raise

    def _apply_ip_bans(self, ip_list: list[str], duration: int) -> None:
        from guard_core.sync.handlers.ipban_handler import ip_ban_manager

        for ip in ip_list:
            try:
                ip_ban_manager.ban_ip(ip, duration, "dynamic_rule")
                self.logger.info(f"Dynamic rule: Banned IP {ip} for {duration}s")
            except Exception as e:
                self.logger.error(f"Failed to ban IP {ip}: {e}")

    def _apply_ip_whitelist(self, ip_list: list[str]) -> None:
        from guard_core.sync.handlers.ipban_handler import ip_ban_manager

        for ip in ip_list:
            try:
                ip_ban_manager.unban_ip(ip)
                self.logger.info(f"Dynamic rule: Whitelisted IP {ip}")
            except Exception as e:
                self.logger.error(f"Failed to whitelist IP {ip}: {e}")

    def _apply_country_rules(self, blocked: list[str], allowed: list[str]) -> None:
        if blocked:
            self.config.blocked_countries = blocked
            self.logger.info(f"Dynamic rule: Blocked countries {blocked}")

        if allowed:
            self.config.whitelist_countries = allowed
            self.logger.info(f"Dynamic rule: Whitelisted countries {allowed}")

    def _apply_rate_limit_rules(self, rules: DynamicRules) -> None:
        if rules.global_rate_limit:
            self.config.rate_limit = rules.global_rate_limit
            if rules.global_rate_window:
                self.config.rate_limit_window = rules.global_rate_window
            message = f"Global rate limit {rules.global_rate_limit}"
            details = f"per {rules.global_rate_window}s"
            self.logger.info(f"Dynamic rule: {message} {details}")

        if rules.endpoint_rate_limits:
            self.config.endpoint_rate_limits = rules.endpoint_rate_limits.copy()
            self.logger.info(
                f"Dynamic rule: Applied endpoint-specific rate limits for "
                f"{len(rules.endpoint_rate_limits)} endpoints: "
                f"{list(rules.endpoint_rate_limits.keys())}"
            )

    def _apply_cloud_provider_rules(self, providers: set[str]) -> None:
        self.config.block_cloud_providers = providers
        self.logger.info(f"Dynamic rule: Blocked cloud providers {providers}")

    def _apply_user_agent_rules(self, user_agents: list[str]) -> None:
        self.config.blocked_user_agents = user_agents
        self.logger.info(f"Dynamic rule: Blocked user agents {user_agents}")

    def _apply_pattern_rules(self, patterns: list[str]) -> None:
        from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

        for pattern in patterns:
            sus_patterns_handler.add_pattern(pattern)
        self.logger.info(f"Dynamic rule: Added suspicious patterns {patterns}")

    def _apply_feature_toggles(self, rules: DynamicRules) -> None:
        if rules.enable_penetration_detection is not None:
            self.config.enable_penetration_detection = (
                rules.enable_penetration_detection
            )
            details = f"Penetration detection {rules.enable_penetration_detection}"
            self.logger.info(f"Dynamic rule: {details}")

        if rules.enable_ip_banning is not None:
            self.config.enable_ip_banning = rules.enable_ip_banning
            self.logger.info(f"Dynamic rule: IP banning {rules.enable_ip_banning}")

        if rules.enable_rate_limiting is not None:
            self.config.enable_rate_limiting = rules.enable_rate_limiting
            self.logger.info(
                f"Dynamic rule: Rate limiting {rules.enable_rate_limiting}"
            )

    def _activate_emergency_mode(self, emergency_whitelist: list[str]) -> None:
        self.logger.critical(
            "[EMERGENCY MODE] ACTIVATED - Enhanced security posture enabled"
        )

        self.config.emergency_mode = True
        self.config.emergency_whitelist = emergency_whitelist

        original_threshold = self.config.auto_ban_threshold
        self.config.auto_ban_threshold = max(1, original_threshold // 2)
        message = "Reduced auto-ban threshold"
        details = f"from {original_threshold} to {self.config.auto_ban_threshold}"
        self.logger.warning(f"[EMERGENCY MODE] {message} {details}")

        if self.agent_handler:
            self._send_emergency_event(emergency_whitelist)

    def _send_rule_applied_event(self, rules: DynamicRules) -> None:
        if not self.agent_handler:
            return

        try:
            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="dynamic_rule_applied",
                ip_address="system",
                action_taken="rules_updated",
                reason=f"Applied dynamic rules {rules.rule_id} v{rules.version}",
                metadata={
                    "rule_id": rules.rule_id,
                    "version": rules.version,
                    "ip_bans": len(rules.ip_blacklist),
                    "country_blocks": len(rules.blocked_countries),
                    "emergency_mode": rules.emergency_mode,
                },
            )
            self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send rule applied event: {e}")

    def _send_emergency_event(self, whitelist: list[str]) -> None:
        if not self.agent_handler:
            return

        try:
            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="emergency_mode_activated",
                ip_address="system",
                action_taken="emergency_lockdown",
                reason="[EMERGENCY MODE] activated via dynamic rules",
                metadata={
                    "whitelist_count": len(whitelist),
                    "whitelist": whitelist[:10],
                },
            )
            self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send emergency event: {e}")

    def get_current_rules(self) -> DynamicRules | None:
        return self.current_rules

    def force_update(self) -> None:
        self.update_rules()

    def stop(self) -> None:
        if self.update_task and self.update_task.is_alive():
            self.update_task.join(timeout=5)
            self.update_task = None
            self.logger.info("Stopped dynamic rule update loop")


dynamic_rule_manager = DynamicRuleManager
