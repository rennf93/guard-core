import json
from typing import Any

from guard_core.core.checks.base import SecurityCheck
from guard_core.detection_engine.compiler import PatternCompiler
from guard_core.prompt_injection.canary import CanaryManager
from guard_core.prompt_injection.format_strategies import FormatStrategyFactory
from guard_core.prompt_injection.pattern_detector import PatternDetector
from guard_core.prompt_injection.scorer import InjectionScore, InjectionScorer
from guard_core.prompt_injection.semantic_analyzer import SemanticAnalyzer
from guard_core.prompt_injection.statistical_detector import StatisticalDetector
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import log_activity


class PromptInjectionCheck(SecurityCheck):
    """Security check for prompt injection defense."""

    @property
    def check_name(self) -> str:
        return "prompt_injection"

    def __init__(self, middleware: Any) -> None:
        super().__init__(middleware)

        self.pattern_detector: PatternDetector | None = None
        self.scorer: InjectionScorer | None = None
        self.format_strategy: Any = None
        self.canary_manager: CanaryManager | None = None

        if self.config.enable_prompt_injection_detection:
            self._init_detectors()

    def _init_detectors(self) -> None:
        compiler = PatternCompiler(
            default_timeout=self.config.detection_compiler_timeout
        )

        self.pattern_detector = PatternDetector(
            sensitivity=self.config.prompt_injection_sensitivity,
            custom_patterns=self.config.prompt_injection_custom_patterns,
            compiler=compiler,
        )

        statistical_detector = StatisticalDetector()
        semantic_analyzer = SemanticAnalyzer()

        transformer_detector = None
        if self.config.prompt_injection_enable_ml:
            from guard_core.prompt_injection.transformer_detector import (
                TransformerDetector,
            )

            transformer_detector = TransformerDetector(
                model_name=self.config.prompt_injection_ml_model,
                confidence_threshold=self.config.prompt_injection_ml_threshold,
            )

        self.scorer = InjectionScorer(
            pattern_detector=self.pattern_detector,
            statistical_detector=statistical_detector,
            semantic_analyzer=semantic_analyzer,
            config=self.config,
            transformer_detector=transformer_detector,
        )

        self.format_strategy = FormatStrategyFactory.get_strategy(
            self.config.prompt_injection_format_strategy
        )

        if self.config.prompt_injection_enable_canary:
            redis_manager = (
                getattr(self.middleware, "redis_handler", None)
                if self.config.enable_redis
                else None
            )
            self.canary_manager = CanaryManager(
                redis_manager=redis_manager,
                use_redis=self.config.prompt_injection_store_canaries_redis,
                ttl_seconds=self.config.prompt_injection_canary_ttl,
            )

    async def _should_skip(self, request: GuardRequest) -> bool:
        """Check if this request should skip injection detection."""
        route_config = getattr(request.state, "route_config", None)
        if route_config and not getattr(
            route_config, "enable_prompt_injection_detection", True
        ):
            await self.send_event(
                event_type="decorator_violation",
                request=request,
                action_taken="detection_disabled",
                reason="Prompt injection detection disabled by route decorator",
            )
            return True

        if request.method not in self.config.prompt_injection_methods:
            return True

        if getattr(request.state, "is_whitelisted", False):
            return True

        return False

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        if not self.config.enable_prompt_injection_detection or not self.scorer:
            return None

        if await self._should_skip(request):
            return None

        text = await self._extract_text(request)
        if not text:
            return None

        max_len = self.config.prompt_injection_max_content_length
        if len(text) > max_len:
            text = text[:max_len]

        result = await self.scorer.score(text)

        if not result["is_malicious"]:
            self._store_helpers(request, text)
            return None

        if self.is_passive_mode():
            await self._log_detection(request, result)
            return None

        # Active mode: block
        client_ip = getattr(request.state, "client_ip", "unknown")
        trigger_info = (
            f"Score: {result['total_score']:.2f}, "
            f"Patterns: {result['matched_patterns']}"
        )

        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Prompt injection detected from {client_ip}",
            trigger_info=trigger_info,
            level=self.config.log_suspicious_level,
        )

        await self.send_event(
            event_type="prompt_injection_attempt",
            request=request,
            action_taken="blocked",
            reason=f"Prompt injection detected: {trigger_info}",
            matched_patterns=result["matched_patterns"],
            threat_score=result["total_score"],
        )

        return await self.create_error_response(
            403, "Request blocked: Suspicious input patterns detected"
        )

    async def _extract_text(self, request: GuardRequest) -> str:
        """Extract text content from request body."""
        try:
            body_bytes = await request.body()
            if not body_bytes:
                return ""

            try:
                parsed = json.loads(body_bytes)
            except (json.JSONDecodeError, UnicodeDecodeError):
                return body_bytes.decode("utf-8", errors="ignore")

            if isinstance(parsed, str):
                return parsed

            if isinstance(parsed, dict):
                texts: list[str] = []
                for field_name in self.config.prompt_injection_text_fields:
                    if field_name in parsed and isinstance(parsed[field_name], str):
                        texts.append(parsed[field_name])
                return " ".join(texts)

            return ""
        except Exception:
            return ""

    def _store_helpers(self, request: GuardRequest, text: str) -> None:
        """Store sanitized input and helper functions in request.state."""
        state = request.state

        if self.format_strategy:
            state.prompt_guard_sanitized = self.format_strategy.apply(text)
        else:
            state.prompt_guard_sanitized = text

        if self.canary_manager:
            state.prompt_guard_inject_canary = self.canary_manager.inject_canary
            state.prompt_guard_verify_output = self.canary_manager.verify_output

    async def _log_detection(
        self, request: GuardRequest, result: InjectionScore
    ) -> None:
        """Log detection in passive mode."""
        client_ip = getattr(request.state, "client_ip", "unknown")
        trigger_info = (
            f"Score: {result['total_score']:.2f}, "
            f"Patterns: {result['matched_patterns']}"
        )

        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Prompt injection detected (passive mode): {client_ip}",
            passive_mode=True,
            trigger_info=trigger_info,
            level=self.config.log_suspicious_level,
        )

        await self.send_event(
            event_type="prompt_injection_attempt",
            request=request,
            action_taken="logged_only",
            reason=f"Prompt injection detected (passive): {trigger_info}",
            matched_patterns=result["matched_patterns"],
            threat_score=result["total_score"],
            passive_mode=True,
        )
