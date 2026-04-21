import json
<<<<<<< Updated upstream
from typing import Any

from guard_core.core.checks.base import SecurityCheck
from guard_core.detection_engine.compiler import PatternCompiler
from guard_core.prompt_injection.canary import CanaryManager
from guard_core.prompt_injection.format_strategies import FormatStrategyFactory
from guard_core.prompt_injection.pattern_detector import PatternDetector
from guard_core.prompt_injection.scorer import InjectionScore, InjectionScorer
from guard_core.prompt_injection.semantic_analyzer import SemanticAnalyzer
from guard_core.prompt_injection.statistical_detector import StatisticalDetector
=======
from typing import TYPE_CHECKING

from guard_core.core.checks.base import SecurityCheck
from guard_core.prompt_injection import PromptGuard, PromptInjectionAttempt
>>>>>>> Stashed changes
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import log_activity

<<<<<<< Updated upstream

class PromptInjectionCheck(SecurityCheck):
    """Security check for prompt injection defense."""
=======
if TYPE_CHECKING:
    from guard_core.protocols.middleware_protocol import GuardMiddlewareProtocol


_TEXT_FIELDS = ("prompt", "message", "content", "text", "query", "input", "instruction")


class PromptInjectionCheck(SecurityCheck):
    def __init__(self, middleware: "GuardMiddlewareProtocol") -> None:
        super().__init__(middleware)

        self.prompt_guard: PromptGuard | None = None
        if self.config.enable_prompt_injection_defense:
            self.prompt_guard = PromptGuard(
                protection_level=self.config.prompt_injection_protection_level,
                format_strategy=self.config.prompt_injection_format_strategy,
                pattern_sensitivity=self.config.prompt_injection_pattern_sensitivity,
                custom_patterns=self.config.prompt_injection_custom_patterns,
                redis_manager=(
                    self.middleware.redis_handler if self.config.enable_redis else None
                ),
                enable_canary=self.config.prompt_injection_enable_canary,
                use_redis_for_canaries=(
                    self.config.prompt_injection_store_canaries_redis
                ),
                semantic_fuzzy_threshold=(
                    self.config.prompt_injection_semantic_fuzzy_threshold
                ),
                semantic_proximity_window=(
                    self.config.prompt_injection_semantic_proximity_window
                ),
                semantic_enable_synonym=(
                    self.config.prompt_injection_semantic_enable_synonym
                ),
                semantic_enable_fuzzy=(
                    self.config.prompt_injection_semantic_enable_fuzzy
                ),
                semantic_enable_proximity=(
                    self.config.prompt_injection_semantic_enable_proximity
                ),
                enable_embedding_detection=(
                    self.config.prompt_injection_enable_embedding_detection
                ),
                embedding_model=self.config.prompt_injection_embedding_model,
                embedding_threshold=self.config.prompt_injection_embedding_threshold,
                enable_transformer_detection=(
                    self.config.prompt_injection_enable_transformer_detection
                ),
                transformer_model=self.config.prompt_injection_transformer_model,
                transformer_threshold=(
                    self.config.prompt_injection_transformer_threshold
                ),
                transformer_revision=(
                    self.config.prompt_injection_transformer_revision
                ),
                enable_statistical_boost=(
                    self.config.prompt_injection_enable_statistical_boost
                ),
                statistical_boost_weight=(
                    self.config.prompt_injection_statistical_boost_weight
                ),
                context_boost_weight=(
                    self.config.prompt_injection_context_boost_weight
                ),
                context_max_history=(self.config.prompt_injection_context_max_history),
                detection_threshold=(self.config.prompt_injection_detection_threshold),
                rag_detection_threshold=(
                    self.config.prompt_injection_rag_detection_threshold
                ),
                long_input_strategy=(self.config.prompt_injection_long_input_strategy),
                transformer_window_size=(self.config.prompt_injection_window_size),
                transformer_window_overlap=(
                    self.config.prompt_injection_window_overlap
                ),
                embedding_window_chars=(
                    self.config.prompt_injection_embedding_window_chars
                ),
                embedding_window_overlap_chars=(
                    self.config.prompt_injection_embedding_window_overlap_chars
                ),
                enable_language_routing=(
                    self.config.prompt_injection_enable_language_routing
                ),
                multilingual_transformer_model=(
                    self.config.prompt_injection_multilingual_transformer_model
                ),
                multilingual_scoring_scheme=(
                    self.config.prompt_injection_multilingual_scoring_scheme
                ),
                multilingual_injection_label_idx=(
                    self.config.prompt_injection_multilingual_injection_label_idx
                ),
                multilingual_transformer_threshold=(
                    self.config.prompt_injection_multilingual_transformer_threshold
                ),
            )
>>>>>>> Stashed changes

    @property
    def check_name(self) -> str:
        return "prompt_injection"

<<<<<<< Updated upstream
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
=======
    async def check(self, request: GuardRequest) -> GuardResponse | None:
        if not self.config.enable_prompt_injection_defense or not self.prompt_guard:
            return None

        if request.method not in ("POST", "PUT", "PATCH"):
            return None

        body = await self._get_request_body(request)
        if body is None:
            return None

        text_content = self._extract_text_content(body)
        if not text_content:
            return None

        try:
            self._apply_protection(request, text_content)
            return None
        except PromptInjectionAttempt as exc:
            return await self._handle_injection_attempt(request, exc)

    def _apply_protection(self, request: GuardRequest, text_content: str) -> None:
        assert self.prompt_guard is not None
        session_id = self._get_session_id(request)
        sanitized = self.prompt_guard.protect_input(text_content, session_id)

        request.state.prompt_guard_sanitized = sanitized
        request.state.prompt_guard_session_id = session_id
        request.state.prompt_guard_get_system_instruction = (
            self.prompt_guard.get_system_instruction
        )
        request.state.prompt_guard_prepare_system_prompt = (
            self.prompt_guard.prepare_system_prompt
        )
        if self.prompt_guard.enable_canary:
            request.state.prompt_guard_inject_canary = (
                self.prompt_guard.inject_system_canary
            )
            request.state.prompt_guard_verify_output = self.prompt_guard.verify_output

    async def post_response(
        self, request: GuardRequest, response: GuardResponse
    ) -> GuardResponse | None:
        if not self.config.enable_prompt_injection_defense or not self.prompt_guard:
            return None
        if not self.prompt_guard.enable_canary:
            return None
        if not getattr(request.state, "prompt_guard_sanitized", None):
            return None

        body = response.body or b""
        body_text = body.decode("utf-8", errors="ignore")

        if self.prompt_guard.verify_output(body_text):
            return None

        session_id = getattr(request.state, "prompt_guard_session_id", None)
        client_ip = getattr(request.state, "client_ip", "unknown")
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Canary exfiltration detected from {client_ip}",
            trigger_info=f"session={session_id}",
            level=self.config.log_suspicious_level,
        )
        await self.send_event(
            event_type="canary_exfiltration",
            request=request,
            action_taken="blocked",
            reason="Canary token leaked in LLM response",
            session_id=session_id,
        )
        return await self.create_error_response(
            403,
            "Response blocked: Suspicious output patterns detected",
        )

    async def _handle_injection_attempt(
        self, request: GuardRequest, exc: PromptInjectionAttempt
    ) -> GuardResponse:
        client_ip = getattr(request.state, "client_ip", "unknown")
        trigger_info = (
            f"Layer: {exc.detection_layer}, "
            f"Score: {exc.threat_score}, "
            f"Patterns: {exc.matched_patterns}"
>>>>>>> Stashed changes
        )

        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Prompt injection detected from {client_ip}",
            trigger_info=trigger_info,
            level=self.config.log_suspicious_level,
        )

<<<<<<< Updated upstream
=======
        request.state.prompt_guard_detection_info = exc.to_dict()

        await self._record_threat_signal(client_ip, exc)

>>>>>>> Stashed changes
        await self.send_event(
            event_type="prompt_injection_attempt",
            request=request,
            action_taken="blocked",
<<<<<<< Updated upstream
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
=======
            reason=str(exc),
            matched_patterns=exc.matched_patterns,
            detection_layer=exc.detection_layer,
            threat_score=exc.threat_score,
            detection_metadata=exc.detection_metadata,
        )

        return await self.create_error_response(
            403,
            "Request blocked: Suspicious input patterns detected",
        )

    async def _record_threat_signal(
        self, client_ip: str, exc: PromptInjectionAttempt
    ) -> None:
        if not self.config.enable_threat_score_rate_limiting:
            return
        rate_limit_handler = getattr(self.middleware, "rate_limit_handler", None)
        if rate_limit_handler is None:
            return
        score = exc.threat_score if exc.threat_score is not None else 1.0
        try:
            await rate_limit_handler.record_threat_signal(client_ip, float(score))
        except Exception as err:
            self.logger.error(f"Failed to record threat signal: {err}")

    @staticmethod
    async def _get_request_body(
        request: GuardRequest,
    ) -> dict[str, object] | str | None:
        try:
            body_bytes = await request.body()
            if not body_bytes:
                return None
            try:
                parsed = json.loads(body_bytes)
                if isinstance(parsed, dict):
                    return parsed
                return body_bytes.decode("utf-8", errors="ignore")
            except json.JSONDecodeError:
                return body_bytes.decode("utf-8", errors="ignore")
        except Exception:
            return None

    @staticmethod
    def _extract_text_content(body: dict[str, object] | str) -> str:
        if isinstance(body, str):
            return body
        texts: list[str] = []
        for field in _TEXT_FIELDS:
            value = body.get(field)
            if isinstance(value, str):
                texts.append(value)
        for value in body.values():
            if isinstance(value, str) and value not in texts:
                texts.append(value)
        return " ".join(texts)

    @staticmethod
    def _get_session_id(request: GuardRequest) -> str | None:
        session_id = request.headers.get("x-session-id") or request.headers.get(
            "X-Session-ID"
        )
        if session_id:
            return session_id

        cookie_session = PromptInjectionCheck._session_from_cookie(request)
        if cookie_session:
            return cookie_session

        return request.client_host

    @staticmethod
    def _session_from_cookie(request: GuardRequest) -> str | None:
        cookie_header = request.headers.get("cookie") or request.headers.get("Cookie")
        if not cookie_header:
            return None
        for part in cookie_header.split(";"):
            key, _, value = part.strip().partition("=")
            if key == "session_id" and value:
                return value
        return None
>>>>>>> Stashed changes
