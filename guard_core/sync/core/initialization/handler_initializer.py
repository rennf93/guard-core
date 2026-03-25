from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig


class HandlerInitializer:
    def __init__(
        self,
        config: "SecurityConfig",
        redis_handler: Any = None,
        agent_handler: Any = None,
        geo_ip_handler: Any = None,
        rate_limit_handler: Any = None,
        guard_decorator: Any = None,
    ):
        self.config = config
        self.redis_handler = redis_handler
        self.agent_handler = agent_handler
        self.geo_ip_handler = geo_ip_handler
        self.rate_limit_handler = rate_limit_handler
        self.guard_decorator = guard_decorator

    def initialize_redis_handlers(self) -> None:
        if not (self.config.enable_redis and self.redis_handler):
            return

        self.redis_handler.initialize()

        from guard_core.sync.handlers.cloud_handler import cloud_handler
        from guard_core.sync.handlers.ipban_handler import ip_ban_manager
        from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

        if self.config.block_cloud_providers:
            cloud_handler.initialize_redis(
                self.redis_handler,
                self.config.block_cloud_providers,
                ttl=self.config.cloud_ip_refresh_interval,
            )

        ip_ban_manager.initialize_redis(self.redis_handler)
        if self.geo_ip_handler is not None:
            self.geo_ip_handler.initialize_redis(self.redis_handler)
        if self.rate_limit_handler is not None:
            self.rate_limit_handler.initialize_redis(self.redis_handler)
        sus_patterns_handler.initialize_redis(self.redis_handler)

    def initialize_agent_for_handlers(self) -> None:
        if not self.agent_handler:
            return

        from guard_core.sync.handlers.cloud_handler import cloud_handler
        from guard_core.sync.handlers.ipban_handler import ip_ban_manager
        from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

        ip_ban_manager.initialize_agent(self.agent_handler)
        if self.rate_limit_handler is not None:
            self.rate_limit_handler.initialize_agent(self.agent_handler)
        sus_patterns_handler.initialize_agent(self.agent_handler)

        if self.config.block_cloud_providers:
            cloud_handler.initialize_agent(self.agent_handler)

        if self.geo_ip_handler and hasattr(self.geo_ip_handler, "initialize_agent"):
            self.geo_ip_handler.initialize_agent(self.agent_handler)

    def initialize_dynamic_rule_manager(self) -> None:
        if not (self.agent_handler and self.config.enable_dynamic_rules):
            return

        from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager

        dynamic_rule_manager = DynamicRuleManager(self.config)
        dynamic_rule_manager.initialize_agent(self.agent_handler)

        if self.redis_handler:
            dynamic_rule_manager.initialize_redis(self.redis_handler)

    def initialize_agent_integrations(self) -> None:
        if not self.agent_handler:
            return

        self.agent_handler.start()

        if self.redis_handler:
            self.agent_handler.initialize_redis(self.redis_handler)
            self.redis_handler.initialize_agent(self.agent_handler)

        self.initialize_agent_for_handlers()

        if self.guard_decorator and hasattr(self.guard_decorator, "initialize_agent"):
            self.guard_decorator.initialize_agent(self.agent_handler)

        self.initialize_dynamic_rule_manager()
