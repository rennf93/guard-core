from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from guard_core.core.events.metrics import MetricsCollector
    from guard_core.core.events.middleware_events import SecurityEventBus
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
        self.composite_handler: Any = None
        self.event_filter: Any = None
        self.enricher: Any = None

    def build_enricher(self) -> Any | None:
        if not self.config.enable_enrichment:
            return None
        from guard_core.core.events.enricher import EnrichmentContext, EventEnricher

        dynamic_rule_handler: Any = None
        if self.config.enable_dynamic_rules:
            from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager

            dynamic_rule_handler = DynamicRuleManager(self.config)

        behavior_tracker: Any = None
        if self.guard_decorator is not None:
            behavior_tracker = getattr(self.guard_decorator, "behavior_tracker", None)

        context = EnrichmentContext(
            config=self.config,
            agent_handler=self.agent_handler,
            dynamic_rule_handler=dynamic_rule_handler,
            behavior_tracker=behavior_tracker,
        )
        return EventEnricher(context)

    def build_composite_handler(self) -> Any:
        from guard_core.core.events.composite_handler import CompositeAgentHandler

        handlers = []
        if self.agent_handler:
            handlers.append(self.agent_handler)
        if self.config.enable_otel:
            from guard_core.core.events.otel_handler import OtelHandler

            handlers.append(OtelHandler(self.config))
        if self.config.enable_logfire:
            from guard_core.core.events.logfire_handler import LogfireHandler

            handlers.append(LogfireHandler(self.config))
        event_filter = self.build_event_filter()
        self.enricher = self.build_enricher()
        return CompositeAgentHandler(
            handlers, event_filter=event_filter, enricher=self.enricher
        )

    def build_event_filter(self) -> Any:
        from guard_core.core.events.event_types import EventFilter

        return EventFilter(
            muted_event_types=frozenset(self.config.muted_event_types),
            muted_metric_types=frozenset(self.config.muted_metric_types),
        )

    def build_event_bus(self, geo_ip_handler: Any = None) -> "SecurityEventBus":
        from guard_core.core.events.middleware_events import SecurityEventBus

        if self.composite_handler is None or self.event_filter is None:
            raise RuntimeError(
                "Call initialize_agent_integrations() before build_event_bus()."
            )
        return SecurityEventBus(
            agent_handler=self.composite_handler,
            config=self.config,
            geo_ip_handler=geo_ip_handler or self.geo_ip_handler,
            event_filter=self.event_filter,
        )

    def build_metrics_collector(self) -> "MetricsCollector":
        from guard_core.core.events.metrics import MetricsCollector

        if self.composite_handler is None or self.event_filter is None:
            raise RuntimeError(
                "Call initialize_agent_integrations() before build_metrics_collector()."
            )
        return MetricsCollector(
            agent_handler=self.composite_handler,
            config=self.config,
            event_filter=self.event_filter,
        )

    async def initialize_redis_handlers(self) -> None:
        if not (self.config.enable_redis and self.redis_handler):
            return

        await self.redis_handler.initialize()

        from guard_core.handlers.cloud_handler import cloud_handler
        from guard_core.handlers.ipban_handler import ip_ban_manager
        from guard_core.handlers.suspatterns_handler import sus_patterns_handler

        if self.config.block_cloud_providers:
            await cloud_handler.initialize_redis(
                self.redis_handler,
                self.config.block_cloud_providers,
                ttl=self.config.cloud_ip_refresh_interval,
            )

        await ip_ban_manager.initialize_redis(self.redis_handler)
        if self.geo_ip_handler is not None:
            await self.geo_ip_handler.initialize_redis(self.redis_handler)
        if self.rate_limit_handler is not None:
            await self.rate_limit_handler.initialize_redis(self.redis_handler)
        await sus_patterns_handler.initialize_redis(self.redis_handler)

    async def initialize_agent_for_handlers(self) -> None:
        telemetry = self.composite_handler or self.agent_handler
        if telemetry is None:
            return

        from guard_core.handlers.cloud_handler import cloud_handler
        from guard_core.handlers.ipban_handler import ip_ban_manager
        from guard_core.handlers.suspatterns_handler import sus_patterns_handler

        await ip_ban_manager.initialize_agent(telemetry)
        if self.rate_limit_handler is not None:
            await self.rate_limit_handler.initialize_agent(telemetry)
        await sus_patterns_handler.initialize_agent(telemetry)

        if self.config.block_cloud_providers:
            await cloud_handler.initialize_agent(telemetry)

        if self.geo_ip_handler and hasattr(self.geo_ip_handler, "initialize_agent"):
            await self.geo_ip_handler.initialize_agent(telemetry)

    async def initialize_dynamic_rule_manager(self) -> None:
        if not (self.agent_handler and self.config.enable_dynamic_rules):
            return

        from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager

        dynamic_rule_manager = DynamicRuleManager(self.config)
        telemetry = self.composite_handler or self.agent_handler
        await dynamic_rule_manager.initialize_agent(telemetry)

        if self.redis_handler:
            await dynamic_rule_manager.initialize_redis(self.redis_handler)

    async def initialize_agent_integrations(self) -> None:
        if (
            not self.agent_handler
            and not self.config.enable_otel
            and not self.config.enable_logfire
            and not self.config.enable_enrichment
        ):
            return

        self.composite_handler = self.build_composite_handler()
        self.event_filter = self.build_event_filter()

        await self.composite_handler.start()

        if self.agent_handler and self.redis_handler:
            await self.agent_handler.initialize_redis(self.redis_handler)
            await self.redis_handler.initialize_agent(self.agent_handler)

        await self.initialize_agent_for_handlers()

        if self.guard_decorator and hasattr(self.guard_decorator, "initialize_agent"):
            telemetry = self.composite_handler or self.agent_handler
            await self.guard_decorator.initialize_agent(telemetry)

        await self.initialize_dynamic_rule_manager()

    async def shutdown_agent_integrations(self) -> None:
        if self.composite_handler is None:
            return
        await self.composite_handler.stop()
        self.composite_handler = None
        self.event_filter = None
        self.enricher = None
