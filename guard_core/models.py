from collections.abc import Awaitable, Callable
from datetime import datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from typing_extensions import Self

from guard_core.protocols.geo_ip_protocol import GeoIPHandler
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse

if TYPE_CHECKING:
    from guard_agent import AgentConfig


class SecurityConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    trusted_proxies: list[str] = Field(
        default_factory=list,
        description="List of trusted proxy IPs or CIDR ranges for X-Forwarded-For",
    )

    trusted_proxy_depth: int = Field(
        default=1,
        description="How many proxies to expect in the X-Forwarded-For chain",
    )

    trust_x_forwarded_proto: bool = Field(
        default=False,
        description="Trust X-Forwarded-Proto header for HTTPS detection",
    )

    passive_mode: bool = Field(
        default=False,
        description="Enable Log-Only mode. Won't block requests, only log.",
    )

    geo_ip_handler: GeoIPHandler | None = Field(
        default=None,
        description="Geographical IP handler to use for IP geolocation",
    )

    enable_redis: bool = Field(
        default=True,
        description="Enable/disable Redis for distributed state management",
    )

    redis_url: str | None = Field(
        default="redis://localhost:6379",
        description="Redis URL for distributed state management",
    )

    redis_prefix: str = Field(
        default="guard_core:",
        description="Prefix for Redis keys to avoid collisions with other apps",
    )

    whitelist: list[str] | None = Field(
        default=None, description="Allowed IP addresses or CIDR ranges"
    )

    blacklist: list[str] = Field(
        default_factory=list, description="Blocked IP addresses or CIDR ranges"
    )

    whitelist_countries: list[str] = Field(
        default_factory=list,
        description="A list of country codes that are always allowed",
    )

    blocked_countries: list[str] = Field(
        default_factory=list,
        description="A list of country codes that are always blocked",
    )

    blocked_user_agents: list[str] = Field(
        default_factory=list, description="Blocked user agents"
    )

    auto_ban_threshold: int = Field(
        default=10, description="Number of suspicious requests before auto-ban"
    )

    auto_ban_duration: int = Field(
        default=3600, description="Duration of auto-ban in seconds (default: 1 hour)"
    )

    custom_log_file: str | None = Field(
        default=None,
        description="The path to a custom log file for logging security events",
    )

    log_suspicious_level: (
        Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None
    ) = Field(default="WARNING", description="Log level for suspicious requests")

    log_request_level: (
        Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None
    ) = Field(default=None, description="Log level for requests")

    log_format: Literal["text", "json"] = Field(
        default="text",
        description="Log output format: 'text' or 'json' for structured JSON",
    )

    custom_error_responses: dict[int, str] = Field(
        default_factory=dict, description="Custom error for specific HTTP status codes"
    )

    rate_limit: int = Field(
        default=10, description="Maximum requests per rate_limit_window"
    )

    rate_limit_window: int = Field(
        default=60, description="Rate limiting time window (seconds)"
    )

    enable_threat_score_rate_limiting: bool = Field(
        default=False,
        description=(
            "Tighten per-IP rate limits when recent prompt-injection "
            "detections have been recorded for that IP. Requires rate "
            "limiting to be enabled overall. Off by default; opt in to "
            "trade a small per-request Redis query for automatic backoff "
            "on attackers."
        ),
    )

    rate_limit_multiplier_on_threat: float = Field(
        default=0.25,
        description=(
            "Fraction of the configured rate_limit applied when a client IP "
            "has any unexpired threat signal. 0.25 = allow 25% of normal "
            "throughput. Range (0, 1]; 1.0 disables tightening."
        ),
        gt=0.0,
        le=1.0,
    )

    threat_signal_ttl: int = Field(
        default=3600,
        description=(
            "Seconds a recorded threat signal remains in effect when "
            "applying rate_limit_multiplier_on_threat. Default 1h."
        ),
        ge=1,
    )

    enforce_https: bool = Field(
        default=False, description="Whether to enforce HTTPS connections"
    )

    security_headers: dict[str, Any] | None = Field(
        default_factory=lambda: {
            "enabled": True,
            "hsts": {
                "max_age": 31536000,
                "include_subdomains": True,
                "preload": False,
            },
            "csp": None,
            "frame_options": "SAMEORIGIN",
            "content_type_options": "nosniff",
            "xss_protection": "1; mode=block",
            "referrer_policy": "strict-origin-when-cross-origin",
            "permissions_policy": "geolocation=(), microphone=(), camera=()",
            "custom": None,
        },
        description="Security headers configuration",
    )

    custom_request_check: (
        Callable[[GuardRequest], Awaitable[GuardResponse | None]] | None
    ) = Field(default=None, description="Perform additional checks on the request")

    custom_response_modifier: (
        Callable[[GuardResponse], Awaitable[GuardResponse]] | None
    ) = Field(
        default=None,
        description="A custom function to modify the response before it's sent",
    )

    enable_cors: bool = Field(default=False, description="Enable/disable CORS")

    cors_allow_origins: list[str] = Field(
        default_factory=lambda: ["*"], description="Origins allowed in CORS requests"
    )

    cors_allow_methods: list[str] = Field(
        default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        description="Methods allowed in CORS requests",
    )

    cors_allow_headers: list[str] = Field(
        default_factory=lambda: ["*"], description="Headers allowed in CORS requests"
    )

    cors_allow_credentials: bool = Field(
        default=False, description="Whether to allow credentials in CORS requests"
    )

    cors_expose_headers: list[str] = Field(
        default_factory=list, description="Headers exposed in CORS responses"
    )

    cors_max_age: int = Field(
        default=600, description="Maximum age of CORS preflight results"
    )

    block_cloud_providers: set[str] | None = Field(
        default=None, description="Set of cloud provider names to block"
    )

    cloud_ip_refresh_interval: int = Field(
        default=3600,
        description="Interval in seconds between cloud IP range refreshes",
        ge=60,
        le=86400,
    )

    exclude_paths: list[str] = Field(
        default_factory=lambda: [
            "/docs",
            "/redoc",
            "/openapi.json",
            "/openapi.yaml",
            "/favicon.ico",
            "/static",
        ],
        description="Paths to exclude from security checks",
    )

    enable_ip_banning: bool = Field(
        default=True, description="Enable/disable IP banning functionality"
    )

    enable_rate_limiting: bool = Field(
        default=True, description="Enable/disable rate limiting functionality"
    )

    enable_penetration_detection: bool = Field(
        default=True, description="Enable/disable penetration attempt detection"
    )

    ipinfo_token: str | None = Field(
        default=None,
        description="IPInfo API token for IP geolocation. Deprecated. "
        "Create a custom `geo_ip_handler` instead.",
    )

    ipinfo_db_path: Path | None = Field(
        default=Path("data/ipinfo/country_asn.mmdb"),
        description="Path to the IPInfo database file. Deprecated. "
        "Create a custom `geo_ip_handler` instead.",
    )

    enable_agent: bool = Field(
        default=False, description="Enable Guard Agent telemetry and monitoring"
    )

    agent_api_key: str | None = Field(
        default=None, description="API key for Guard Agent SaaS platform"
    )

    agent_endpoint: str = Field(
        default="https://api.fastapi-guard.com",
        description="Guard Agent SaaS platform endpoint",
    )

    agent_project_id: str | None = Field(
        default=None, description="Project ID for organizing telemetry data"
    )

    agent_buffer_size: int = Field(
        default=100, description="Number of events to buffer before auto-flush"
    )

    agent_flush_interval: int = Field(
        default=30, description="Interval in seconds between automatic buffer flushes"
    )

    agent_enable_events: bool = Field(
        default=True, description="Enable sending security events to SaaS platform"
    )

    agent_enable_metrics: bool = Field(
        default=True, description="Enable sending performance metrics to SaaS platform"
    )

    agent_timeout: int = Field(
        default=30, description="Timeout in seconds for agent HTTP requests"
    )

    agent_retry_attempts: int = Field(
        default=3, description="Number of retry attempts for failed requests"
    )

    enable_dynamic_rules: bool = Field(
        default=False, description="Enable dynamic rule updates from SaaS platform"
    )

    dynamic_rule_interval: int = Field(
        default=300, description="Interval in seconds between dynamic rule updates"
    )

    emergency_mode: bool = Field(
        default=False, description="Emergency lockdown mode (set by dynamic rules)"
    )

    emergency_whitelist: list[str] = Field(
        default_factory=list,
        description="Emergency whitelist IPs (set by dynamic rules)",
    )

    endpoint_rate_limits: dict[str, tuple[int, int]] = Field(
        default_factory=dict,
        description="Per-endpoint rate limits set by dynamic rules",
    )

    detection_compiler_timeout: float = Field(
        default=2.0,
        description="Timeout for pattern compilation and matching (seconds)",
        ge=0.1,
        le=10.0,
    )

    detection_max_content_length: int = Field(
        default=10000,
        description="Maximum content length for pattern detection",
        ge=1000,
        le=100000,
    )

    detection_preserve_attack_patterns: bool = Field(
        default=True,
        description="Preserve attack patterns during content truncation",
    )

    detection_semantic_threshold: float = Field(
        default=0.7,
        description="Threshold for semantic attack detection (0.0-1.0)",
        ge=0.0,
        le=1.0,
    )

    detection_anomaly_threshold: float = Field(
        default=3.0,
        description="Standard deviations from mean to consider anomaly",
        ge=1.0,
        le=10.0,
    )

    detection_slow_pattern_threshold: float = Field(
        default=0.1,
        description="Execution time to consider pattern slow (seconds)",
        ge=0.01,
        le=1.0,
    )

    detection_monitor_history_size: int = Field(
        default=1000,
        description="Number of recent metrics to keep in history",
        ge=100,
        le=10000,
    )

    detection_max_tracked_patterns: int = Field(
        default=1000,
        description="Maximum number of patterns to track for performance",
        ge=100,
        le=5000,
    )

<<<<<<< Updated upstream
    # Prompt Injection Defense
    enable_prompt_injection_detection: bool = Field(
        default=False,
        description="Enable prompt injection detection (opt-in)",
    )

    prompt_injection_threshold: float = Field(
        default=0.6,
        description="Score threshold for blocking (0.0-1.0)",
        ge=0.0,
        le=1.0,
    )

    prompt_injection_sensitivity: float = Field(
        default=0.5,
        description="Pattern sensitivity (0.0=strict, 1.0=permissive)",
=======
    enable_prompt_injection_defense: bool = Field(
        default=False,
        description="Enable prompt injection detection on request bodies",
    )

    prompt_injection_protection_level: Literal["disabled", "enabled"] = Field(
        default="enabled",
        description="Prompt injection protection level",
    )

    prompt_injection_pattern_sensitivity: float = Field(
        default=0.5,
        description=(
            "Pattern detector sensitivity; <=0.5 is strict (any match blocks)"
        ),
>>>>>>> Stashed changes
        ge=0.0,
        le=1.0,
    )

    prompt_injection_custom_patterns: list[str] = Field(
        default_factory=list,
<<<<<<< Updated upstream
        description="User-defined regex patterns for injection detection",
=======
        description="Additional regex patterns (ReDoS-validated at load)",
>>>>>>> Stashed changes
    )

    prompt_injection_format_strategy: Literal[
        "repr", "code_block", "byte_string", "xml_tags", "json_escape"
    ] = Field(
<<<<<<< Updated upstream
        default="xml_tags",
        description="Format strategy for sanitizing LLM input",
    )

    prompt_injection_enable_canary: bool = Field(
        default=False,
        description="Enable canary token leak detection",
    )

    prompt_injection_canary_ttl: int = Field(
        default=3600,
        description="Canary token TTL in seconds",
        ge=60,
        le=86400,
    )

    prompt_injection_store_canaries_redis: bool = Field(
        default=True,
        description="Store canary tokens in Redis (falls back to in-memory)",
    )

    prompt_injection_max_content_length: int = Field(
        default=10000,
        description="Maximum text length to analyze for injection",
        ge=100,
        le=100000,
    )

    prompt_injection_text_fields: list[str] = Field(
        default_factory=lambda: [
            "prompt",
            "message",
            "content",
            "text",
            "query",
            "input",
            "instruction",
        ],
        description="JSON body fields to extract text from for analysis",
    )

    prompt_injection_statistical_weight: float = Field(
        default=0.2,
        description="How much statistical signal boosts the score (0.0-1.0)",
        ge=0.0,
        le=1.0,
    )

    prompt_injection_methods: list[str] = Field(
        default_factory=lambda: ["POST", "PUT", "PATCH"],
        description="HTTP methods to check for prompt injection",
    )

    prompt_injection_enable_ml: bool = Field(
        default=False,
        description=(
            "Enable ML-based detection (requires transformers + torch). "
            "Uses ProtectAI DeBERTa model for 99%+ accuracy."
        ),
    )

    prompt_injection_ml_model: str = Field(
        default="protectai/deberta-v3-base-prompt-injection-v2",
        description="HuggingFace model for ML detection",
    )

    prompt_injection_ml_threshold: float = Field(
        default=0.5,
        description="ML model confidence threshold (0.0-1.0)",
=======
        default="repr",
        description="Input sanitization strategy applied before LLM",
    )

    prompt_injection_enable_canary: bool = Field(
        default=True,
        description="Inject canary tokens into system prompts for leak detection",
    )

    prompt_injection_store_canaries_redis: bool = Field(
        default=False,
        description="Use Redis for distributed canary storage",
    )

    prompt_injection_enable_statistical_boost: bool = Field(
        default=True,
        description=(
            "Add a statistical (entropy/encoding/obfuscation) boost to the "
            "pattern score via SemanticAnalyzer"
        ),
    )

    prompt_injection_statistical_boost_weight: float = Field(
        default=0.3,
        description="Weight applied to the statistical boost when combining",
>>>>>>> Stashed changes
        ge=0.0,
        le=1.0,
    )

<<<<<<< Updated upstream
    # TODO: Add type hints to the decorator
    @field_validator("whitelist", "blacklist")  # type: ignore
=======
    prompt_injection_context_boost_weight: float = Field(
        default=0.2,
        description="Weight applied to the context-aware boost when combining",
        ge=0.0,
        le=1.0,
    )

    prompt_injection_context_max_history: int = Field(
        default=50,
        description="Max per-user input history retained by context detector",
        ge=1,
        le=10000,
    )

    prompt_injection_detection_threshold: float = Field(
        default=0.7,
        description="Unified detection threshold; block when score >= threshold",
        ge=0.0,
        le=1.0,
    )

    prompt_injection_rag_detection_threshold: float = Field(
        default=0.6,
        description=(
            "Detection threshold for PromptGuard.protect_rag_content(). Lower "
            "than the chat threshold because retrieved content is typically "
            "longer, less structured, and more likely to embed injection "
            "payloads near the end of benign-looking context."
        ),
        ge=0.0,
        le=1.0,
    )

    prompt_injection_semantic_fuzzy_threshold: float = Field(
        default=0.85,
        description="Minimum similarity for semantic fuzzy matches",
        ge=0.0,
        le=1.0,
    )

    prompt_injection_semantic_proximity_window: int = Field(
        default=5,
        description="Max tokens between related terms for proximity match",
        ge=1,
        le=100,
    )

    prompt_injection_semantic_enable_synonym: bool = Field(
        default=True,
        description="Enable synonym expansion in semantic matcher",
    )

    prompt_injection_semantic_enable_fuzzy: bool = Field(
        default=True,
        description="Enable fuzzy matching in semantic matcher",
    )

    prompt_injection_semantic_enable_proximity: bool = Field(
        default=True,
        description="Enable proximity matching in semantic matcher",
    )

    prompt_injection_enable_embedding_detection: bool = Field(
        default=False,
        description=(
            "Enable sentence-transformer embedding similarity detector "
            "(requires guard-core[prompt_injection])"
        ),
    )

    prompt_injection_embedding_model: str = Field(
        default="sentence-transformers/all-MiniLM-L6-v2",
        description="Model name for embedding detector",
    )

    prompt_injection_embedding_threshold: float = Field(
        default=0.5,
        description="Cosine similarity threshold for embedding detector",
        ge=0.0,
        le=1.0,
    )

    prompt_injection_enable_transformer_detection: bool = Field(
        default=False,
        description=(
            "Enable DeBERTa-based transformer classifier "
            "(requires guard-core[prompt_injection])"
        ),
    )

    prompt_injection_transformer_model: str = Field(
        default="protectai/deberta-v3-base-prompt-injection",
        description="HuggingFace model id for transformer classifier",
    )

    prompt_injection_transformer_threshold: float = Field(
        default=0.5,
        description="Confidence threshold for transformer classifier",
        ge=0.0,
        le=1.0,
    )

    prompt_injection_transformer_revision: str = Field(
        default="main",
        description="Git revision (commit SHA, tag, or branch) to pin HuggingFace "
        "transformer model weights",
    )

    prompt_injection_long_input_strategy: Literal["max", "mean", "any"] = Field(
        default="max",
        description=(
            "How to aggregate per-window scores when input exceeds the "
            "transformer / embedding max sequence length. 'max' (default) "
            "is safest for detection; 'mean' is conservative; 'any' fires "
            "if any window is above the threshold."
        ),
    )

    prompt_injection_window_size: int = Field(
        default=512,
        description="Transformer token window size for long-input splitting",
        ge=64,
    )

    prompt_injection_window_overlap: int = Field(
        default=64,
        description=(
            "Transformer token window overlap so payloads spanning a "
            "window boundary are seen whole by at least one window"
        ),
        ge=0,
    )

    prompt_injection_embedding_window_chars: int = Field(
        default=96,
        description=(
            "Embedding character window size for long-input splitting. "
            "Measured sweep against the built-in attack template corpus: "
            "an embedded 40-80-char injection payload scores 0.67 at "
            "window=64, 0.61 at window=96, 0.35 at window=128, <0.25 at "
            "≥256. Default 96 keeps the payload isolated enough to cross "
            "the 0.5 similarity threshold without over-slicing normal "
            "chat inputs. The prior 1024-char default produced zero "
            "embedding hits on the RAG benchmark — this fixes the layer."
        ),
        ge=32,
    )

    prompt_injection_embedding_window_overlap_chars: int = Field(
        default=24,
        description=(
            "Embedding character window overlap for long-input splitting. "
            "Sized to 25% of window_chars so a payload spanning a window "
            "boundary is always seen whole by at least one window."
        ),
        ge=0,
    )

    prompt_injection_enable_language_routing: bool = Field(
        default=False,
        description=(
            "Route non-English input to a multilingual transformer model. "
            "Requires lingua-language-detector (bundled in the "
            "prompt_injection extra) and the multilingual transformer "
            "weights. Off by default."
        ),
    )

    prompt_injection_multilingual_transformer_model: str = Field(
        default="proventra/mdeberta-v3-base-prompt-injection",
        description=(
            "HuggingFace model id used when prompt_injection_enable_"
            "language_routing is True and the detected language is not "
            "English. Default proventra/mdeberta-v3-base-prompt-injection "
            "(non-gated MIT, mDeBERTa-v3 multilingual base). Measured on "
            "the 5685-sample non-English eval corpus (DE/ES/FR/IT/JA/NL/PT/"
            "TR/ZH): P=0.985 R=0.857 F1=0.916 FPR=0.010 at threshold=0.5. "
            "See benchmarks/prompt_injection/results/multilingual.json."
        ),
    )

    prompt_injection_multilingual_scoring_scheme: Literal[
        "softmax", "sigmoid_binary"
    ] = Field(
        default="softmax",
        description=(
            "Output head shape of the multilingual model. 'softmax' "
            "(two-logit binary SAFE/INJECTION) or 'sigmoid_binary' "
            "(independent per-label logits, read the injection label "
            "through sigmoid). DeBERTa-style checkpoints are softmax; "
            "mmBERT-v3.5 is sigmoid_binary."
        ),
    )

    prompt_injection_multilingual_injection_label_idx: int = Field(
        default=1,
        description=(
            "Logit index that holds the INJECTION score for the "
            "multilingual model. DeBERTa-style checkpoints use idx=1; "
            "mmBERT-v3.5 has prompt_injection at idx=0."
        ),
        ge=0,
    )

    prompt_injection_multilingual_transformer_threshold: float = Field(
        default=0.65,
        description=(
            "Confidence threshold applied to the INJECTION class "
            "probability of the multilingual model. Calibrated on a 3,119-"
            "sample stratified val split of the multilingual eval corpus: "
            "0.65 maximises recall subject to FPR ≤ 0.01. Held-out test "
            "numbers at this threshold: P=0.996 R=0.524 F1=0.686 FPR=0.008. "
            "See benchmarks/prompt_injection/results/multilingual_"
            "calibration.json for the full sweep."
        ),
        ge=0.0,
        le=1.0,
    )

    @field_validator("whitelist", "blacklist")
    @classmethod
>>>>>>> Stashed changes
    def validate_ip_lists(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None

        validated = []
        for entry in v:
            try:
                if "/" in entry:
                    network = ip_network(entry, strict=False)
                    validated.append(str(network))
                else:
                    addr = ip_address(entry)
                    validated.append(str(addr))
            except ValueError:
                raise ValueError(f"Invalid IP or CIDR range: {entry}") from None
        return validated

    @field_validator("trusted_proxies")
    @classmethod
    def validate_trusted_proxies(cls, v: list[str]) -> list[str]:
        if not v:
            return []

        validated = []
        for entry in v:
            try:
                if "/" in entry:
                    network = ip_network(entry, strict=False)
                    validated.append(str(network))
                else:
                    addr = ip_address(entry)
                    validated.append(str(addr))
            except ValueError:
                raise ValueError(f"Invalid proxy IP or CIDR range: {entry}") from None
        return validated

    @field_validator("trusted_proxy_depth")
    @classmethod
    def validate_proxy_depth(cls, v: int) -> int:
        if v < 1:
            raise ValueError("trusted_proxy_depth must be at least 1")
        return v

    @field_validator("block_cloud_providers", mode="before")
    @classmethod
    def validate_cloud_providers(cls, v: Any) -> set[str]:
        valid_providers = {"AWS", "GCP", "Azure"}
        if v is None:
            return set()
        return {p for p in v if p in valid_providers}

    @model_validator(mode="after")
    def validate_geo_ip_handler_exists(self) -> Self:
        if self.geo_ip_handler is None and (
            self.blocked_countries or self.whitelist_countries
        ):
            if self.ipinfo_token:
                from guard_core.handlers.ipinfo_handler import IPInfoManager

                self.geo_ip_handler = IPInfoManager(
                    token=self.ipinfo_token,
                    db_path=self.ipinfo_db_path,
                )
            else:
                raise ValueError(
                    "geo_ip_handler is required "
                    "if blocked_countries or whitelist_countries is set"
                )
        return self

    @model_validator(mode="after")
    def validate_agent_config(self) -> Self:
        if self.enable_agent and not self.agent_api_key:
            raise ValueError("agent_api_key is required when enable_agent is True")

        if self.enable_dynamic_rules and not self.enable_agent:
            raise ValueError(
                "enable_agent must be True when enable_dynamic_rules is True"
            )

        return self

    def to_agent_config(self) -> "AgentConfig | None":
        if not self.enable_agent or not self.agent_api_key:
            return None

        try:
            from guard_agent import AgentConfig

            return AgentConfig(
                api_key=self.agent_api_key,
                endpoint=self.agent_endpoint,
                project_id=self.agent_project_id,
                buffer_size=self.agent_buffer_size,
                flush_interval=self.agent_flush_interval,
                enable_events=self.agent_enable_events,
                enable_metrics=self.agent_enable_metrics,
                timeout=self.agent_timeout,
                retry_attempts=self.agent_retry_attempts,
            )
        except ImportError:
            return None


class DynamicRules(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    rule_id: str = Field(description="Unique rule ID")
    version: int = Field(description="Rule version number")
    timestamp: datetime = Field(description="Rule creation/update timestamp")
    expires_at: datetime | None = Field(
        default=None, description="Rule expiration time"
    )
    ttl: int = Field(default=300, description="Cache TTL in seconds")

    ip_blacklist: list[str] = Field(default_factory=list, description="IPs to ban")
    ip_whitelist: list[str] = Field(default_factory=list, description="IPs to allow")
    ip_ban_duration: int = Field(default=3600, description="Ban duration in seconds")

    blocked_countries: list[str] = Field(
        default_factory=list, description="Countries to block"
    )
    whitelist_countries: list[str] = Field(
        default_factory=list, description="Countries to allow"
    )

    global_rate_limit: int | None = Field(default=None, description="Global rate limit")
    global_rate_window: int | None = Field(
        default=None, description="Global rate window"
    )
    endpoint_rate_limits: dict[str, tuple[int, int]] = Field(
        default_factory=dict,
        description="Per-endpoint rate limits {endpoint: (requests, window)}",
    )

    blocked_cloud_providers: set[str] = Field(
        default_factory=set, description="Cloud providers to block"
    )

    blocked_user_agents: list[str] = Field(
        default_factory=list, description="User agents to block"
    )

    suspicious_patterns: list[str] = Field(
        default_factory=list, description="Additional suspicious patterns"
    )

    enable_penetration_detection: bool | None = Field(
        default=None, description="Override penetration detection setting"
    )
    enable_ip_banning: bool | None = Field(
        default=None, description="Override IP banning setting"
    )
    enable_rate_limiting: bool | None = Field(
        default=None, description="Override rate limiting setting"
    )

    emergency_mode: bool = Field(default=False, description="Emergency lockdown mode")
    emergency_whitelist: list[str] = Field(
        default_factory=list, description="Emergency whitelist IPs"
    )
