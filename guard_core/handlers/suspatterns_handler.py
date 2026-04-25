import re
import time
from datetime import datetime, timezone
from typing import Any

from guard_core.detection_engine import (
    ContentPreprocessor,
    PatternCompiler,
    PerformanceMonitor,
    SemanticAnalyzer,
)

_CTX_XSS = frozenset({"query_param", "header", "request_body", "unknown"})
_CTX_SQLI = frozenset({"query_param", "request_body", "unknown"})
_CTX_DIR_TRAVERSAL = frozenset({"url_path", "query_param", "request_body", "unknown"})
_CTX_CMD_INJECTION = frozenset({"query_param", "request_body", "unknown"})
_CTX_FILE_INCLUSION = frozenset({"url_path", "query_param", "request_body", "unknown"})
_CTX_LDAP = frozenset({"query_param", "request_body", "unknown"})
_CTX_XML = frozenset({"header", "request_body", "unknown"})
_CTX_SSRF = frozenset({"query_param", "request_body", "unknown"})
_CTX_NOSQL = frozenset({"query_param", "request_body", "unknown"})
_CTX_FILE_UPLOAD = frozenset({"header", "request_body", "unknown"})
_CTX_PATH_TRAVERSAL = frozenset({"url_path", "query_param", "request_body", "unknown"})
_CTX_TEMPLATE = frozenset({"query_param", "request_body", "unknown"})
_CTX_HTTP_SPLIT = frozenset({"header", "query_param", "request_body", "unknown"})
_CTX_SENSITIVE_FILE = frozenset({"url_path", "request_body", "unknown"})
_CTX_CMS_PROBING = frozenset({"url_path", "request_body", "unknown"})
_CTX_RECON = frozenset({"url_path", "unknown"})
_CTX_ALL = frozenset({"query_param", "header", "url_path", "request_body", "unknown"})


ALL_DETECTION_CATEGORIES: frozenset[str] = frozenset(
    {
        "xss",
        "sqli",
        "dir_traversal",
        "path_traversal",
        "cmd_injection",
        "file_inclusion",
        "ldap",
        "xml",
        "ssrf",
        "nosql",
        "file_upload",
        "template",
        "http_split",
        "sensitive_file",
        "cms_probing",
        "recon",
    }
)

CATEGORY_CONTEXT_MAP: dict[str, frozenset[str]] = {
    "xss": _CTX_XSS,
    "sqli": _CTX_SQLI,
    "dir_traversal": _CTX_DIR_TRAVERSAL,
    "path_traversal": _CTX_PATH_TRAVERSAL,
    "cmd_injection": _CTX_CMD_INJECTION,
    "file_inclusion": _CTX_FILE_INCLUSION,
    "ldap": _CTX_LDAP,
    "xml": _CTX_XML,
    "ssrf": _CTX_SSRF,
    "nosql": _CTX_NOSQL,
    "file_upload": _CTX_FILE_UPLOAD,
    "template": _CTX_TEMPLATE,
    "http_split": _CTX_HTTP_SPLIT,
    "sensitive_file": _CTX_SENSITIVE_FILE,
    "cms_probing": _CTX_CMS_PROBING,
    "recon": _CTX_RECON,
}


class SusPatternsManager:
    _instance = None
    _config = None

    _pattern_definitions: list[tuple[str, frozenset[str], str]] = [
        (r"<script[^>]*>[^<]*<\/script\s*>", _CTX_XSS, "xss"),
        (r"javascript:\s*[^\s]+", _CTX_XSS, "xss"),
        (
            r"(?:on(?:error|load|click|mouseover|submit|mouse|unload|change|focus|"
            r"blur|drag))=(?:[\"'][^\"']*[\"']|[^\s>]+)",
            _CTX_XSS,
            "xss",
        ),
        (
            r"(?:<[^>]+\s+(?:href|src|data|action)\s*=[\s\"\']*(?:javascript|"
            r"vbscript|data):)",
            _CTX_XSS,
            "xss",
        ),
        (
            r"(?:<[^>]+style\s*=[\s\"\']*[^>\"\']*(?:expression|behavior|url)\s*\("
            r"[^)]*\))",
            _CTX_XSS,
            "xss",
        ),
        (r"(?:<object[^>]*>[\s\S]*<\/object\s*>)", _CTX_XSS, "xss"),
        (r"(?:<embed[^>]*>[\s\S]*<\/embed\s*>)", _CTX_XSS, "xss"),
        (r"(?:<applet[^>]*>[\s\S]*<\/applet\s*>)", _CTX_XSS, "xss"),
        (r"(?i)SELECT\s+[\w\s,\*]+\s+FROM\s+[\w\s\._]+", _CTX_SQLI, "sqli"),
        (r"(?i)UNION\s+(?:ALL\s+)?SELECT", _CTX_SQLI, "sqli"),
        (
            r"(?i)('\s*(?:OR|AND)\s*[\(\s]*'?[\d\w]+\s*(?:=|LIKE|<|>|<=|>=)\s*"
            r"[\(\s]*'?[\d\w]+)",
            _CTX_SQLI,
            "sqli",
        ),
        (
            r"(?i)(UNION\s+(?:ALL\s+)?SELECT\s+(?:NULL[,\s]*)+|\(\s*SELECT\s+"
            r"(?:@@|VERSION))",
            _CTX_SQLI,
            "sqli",
        ),
        (r"(?i)(?:INTO\s+(?:OUTFILE|DUMPFILE)\s+'[^']+')", _CTX_SQLI, "sqli"),
        (r"(?i)(?:LOAD_FILE\s*\([^)]+\))", _CTX_SQLI, "sqli"),
        (r"(?i)(?:BENCHMARK\s*\(\s*\d+\s*,)", _CTX_SQLI, "sqli"),
        (r"(?i)(?:SLEEP\s*\(\s*\d+\s*\))", _CTX_SQLI, "sqli"),
        (
            r"(?i)(?:\/\*![0-9]*\s*(?:OR|AND|UNION|SELECT|INSERT|DELETE|DROP|"
            r"CONCAT|CHAR|UPDATE)\b)",
            _CTX_SQLI,
            "sqli",
        ),
        (r"(?:\.\.\/|\.\.\\)(?:\.\.\/|\.\.\\)+", _CTX_DIR_TRAVERSAL, "dir_traversal"),
        (
            r"(?:/etc/(?:passwd|shadow|group|hosts|motd|issue|mysql/my.cnf|ssh/"
            r"ssh_config)$)",
            _CTX_DIR_TRAVERSAL,
            "dir_traversal",
        ),
        (
            r"(?:boot\.ini|win\.ini|system\.ini|config\.sys)\s*$",
            _CTX_DIR_TRAVERSAL,
            "dir_traversal",
        ),
        (r"(?:\/proc\/self\/environ$)", _CTX_DIR_TRAVERSAL, "dir_traversal"),
        (r"(?:\/var\/log\/[^\/]+$)", _CTX_DIR_TRAVERSAL, "dir_traversal"),
        (
            r";\s*(?:ls|cat|rm|chmod|chown|wget|curl|nc|netcat|ping|telnet)\s+"
            r"-[a-zA-Z]+\s+",
            _CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        (
            r"\|\s*(?:wget|curl|fetch|lwp-download|lynx|links|GET)\s+",
            _CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        (
            r"(?:[;&|`]\s*(?:\$\([^)]+\)|\$\{[^}]+\}))",
            _CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        (
            r"(?:^|;)\s*(?:bash|sh|ksh|csh|tsch|zsh|ash)\s+-[a-zA-Z]+",
            _CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        (
            r"\b(?:eval|system|exec|shell_exec|passthru|popen|proc_open)\s*\(",
            _CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        (
            r"(?:php|data|zip|rar|file|glob|expect|input|phpinfo|zlib|phar|ssh2|"
            r"rar|ogg|expect)://[^\s]+",
            _CTX_FILE_INCLUSION,
            "file_inclusion",
        ),
        (
            r"(?:\/\/[0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*(:[0-9]+)?(?:\/?)(?:"
            r"[a-zA-Z0-9\-\.\?,'/\\\+&amp;%\$#_]*)?)",
            _CTX_FILE_INCLUSION,
            "file_inclusion",
        ),
        (r"\(\s*[|&]\s*\(\s*[^)]+=[*]", _CTX_LDAP, "ldap"),
        (r"(?:\*(?:[\s\d\w]+\s*=|=\s*[\d\w\s]+))", _CTX_LDAP, "ldap"),
        (r"(?:\(\s*[&|]\s*)", _CTX_LDAP, "ldap"),
        (r"<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>", _CTX_XML, "xml"),
        (r"(?:<!\[CDATA\[.*?\]\]>)", _CTX_XML, "xml"),
        (r"(?:<\?xml.*?\?>)", _CTX_XML, "xml"),
        (
            r"(?:^|\s|/)(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::(?:\d*)\]|(?:169\.254|192\.168|10\.|"
            r"172\.(?:1[6-9]|2[0-9]|3[01]))\.\d+)(?:\s|$|/)",
            _CTX_SSRF,
            "ssrf",
        ),
        (r"(?:file|dict|gopher|jar|tftp)://[^\s]+", _CTX_SSRF, "ssrf"),
        (
            r"\{\s*\$(?:where|gt|lt|ne|eq|regex|in|nin|all|size|exists|type|mod|"
            r"options):",
            _CTX_NOSQL,
            "nosql",
        ),
        (r"(?:\{\s*\$[a-zA-Z]+\s*:\s*(?:\{|\[))", _CTX_NOSQL, "nosql"),
        (
            r"(?i)filename=[\"'].*?\.(?:php\d*|phar|phtml|exe|jsp|asp|aspx|sh|"
            r"bash|rb|py|pl|cgi|com|bat|cmd|vbs|vbe|js|ws|wsf|msi|hta)[\"\']",
            _CTX_FILE_UPLOAD,
            "file_upload",
        ),
        (
            r"(?:%2e%2e|%252e%252e|%uff0e%uff0e|%c0%ae%c0%ae|%e0%40%ae|%c0%ae"
            r"%e0%80%ae|%25c0%25ae)/",
            _CTX_PATH_TRAVERSAL,
            "path_traversal",
        ),
        (
            r"\{\{\s*[^\}]+(?:system|exec|popen|eval|require|include)\s*\}\}",
            _CTX_TEMPLATE,
            "template",
        ),
        (
            r"\{\%\s*[^\%]+(?:system|exec|popen|eval|require|include)\s*\%\}",
            _CTX_TEMPLATE,
            "template",
        ),
        (
            r"[\r\n]\s*(?:HTTP\/[0-9.]+|Location:|Set-Cookie:)",
            _CTX_HTTP_SPLIT,
            "http_split",
        ),
        (r"(?:^|/)\.env(?:\.\w+)?(?:\?|$|/)", _CTX_SENSITIVE_FILE, "sensitive_file"),
        (
            r"(?:^|/)[\w-]*config[\w-]*\."
            r"(?:env|yml|yaml|json|toml|ini|xml|conf)(?:\?|$)",
            _CTX_SENSITIVE_FILE,
            "sensitive_file",
        ),
        (r"(?:^|/)[\w./-]*\.map(?:\?|$)", _CTX_SENSITIVE_FILE, "sensitive_file"),
        (
            r"(?:^|/)[\w./-]*\."
            r"(?:ts|tsx|jsx|py|rb|java|go|rs|php|pl|sh|sql)(?:\?|$)",
            _CTX_SENSITIVE_FILE,
            "sensitive_file",
        ),
        (r"(?:^|/)\.(?:git|svn|hg|bzr)(?:/|$)", _CTX_SENSITIVE_FILE, "sensitive_file"),
        (
            r"(?:^|/)(?:wp-(?:admin|login|content|includes|config)"
            r"|administrator|xmlrpc)\.?(?:php)?(?:/|$|\?)",
            _CTX_CMS_PROBING,
            "cms_probing",
        ),
        (
            r"(?:^|/)(?:phpinfo|info|test|php_info)\.php(?:\?|$)",
            _CTX_CMS_PROBING,
            "cms_probing",
        ),
        (
            r"(?:^|/)[\w./-]*\."
            r"(?:bak|backup|old|orig|save|swp|swo|tmp|temp)(?:\?|$)",
            _CTX_CMS_PROBING,
            "cms_probing",
        ),
        (
            r"(?:^|/)(?:\.htaccess|\.htpasswd|\.DS_Store|Thumbs\.db"
            r"|\.npmrc|\.dockerenv|web\.config)(?:\?|$)",
            _CTX_CMS_PROBING,
            "cms_probing",
        ),
        (
            r"(?:^|/)[\w./-]*\.(?:asp|aspx|jsp|jsa|jhtml|shtml|cfm|cgi|do|action"
            r"|lua|inc|woa|nsf|esp)(?:\?|$)",
            _CTX_RECON,
            "recon",
        ),
        (
            r"^/(?:management|system|version|config_dump|credentials)(?:/|$|\?)",
            _CTX_RECON,
            "recon",
        ),
        (
            r"(?:^|/)(?:actuator|server-status|telescope)(?:/|$|\?)",
            _CTX_RECON,
            "recon",
        ),
        (
            r"(?:CSCOE|dana-(?:na|cached)|sslvpn|RDWeb|/owa/|/ecp/"
            r"|global-protect|ssl-vpn/|svpn/|sonicui|/remote/login"
            r"|myvpn|vpntunnel|versa/login)",
            _CTX_RECON,
            "recon",
        ),
        (
            r"(?:^|/)(?:geoserver|confluence|nifi|ScadaBR|pandora_console"
            r"|centreon|kylin|decisioncenter|evox|MagicInfo|metasys"
            r"|officescan|helpdesk|ignite)(?:/|$|\?|\.|-)",
            _CTX_RECON,
            "recon",
        ),
        (r"(?:^|/)cgi-(?:bin|mod)/", _CTX_RECON, "recon"),
        (
            r"(?:^|/)(?:HNAP1|IPCamDesc\.xml|SDK/webLanguage)(?:\?|$|/)",
            _CTX_RECON,
            "recon",
        ),
        (r"^/(?:language|languages)/", _CTX_RECON, "recon"),
        (
            r"(?:^|/)(?:robots\.txt|sitemap\.xml|security\.txt|readme\.txt"
            r"|README\.md|CHANGELOG|pom\.xml|build\.gradle|appsettings\.json"
            r"|crossdomain\.xml)(?:\?|$|\.)",
            _CTX_RECON,
            "recon",
        ),
        (
            r"(?:^|/)(?:sap|ise|nidp|cslu|rustfs|developmentserver"
            r"|fog/management|lms/db|json/login_session|sms_mp"
            r"|plugin/webs_model|wsman|am_bin)(?:/|$|\?)",
            _CTX_RECON,
            "recon",
        ),
        (r"(?:nmaplowercheck|nice\s+ports|Trinity\.txt)", _CTX_RECON, "recon"),
        (r"(?:^|/)\.(?:openclaw|clawdbot)(?:/|$)", _CTX_RECON, "recon"),
        (r"^/(?:default|inicio|indice|localstart)(?:\.|/|$|\?)", _CTX_RECON, "recon"),
        (
            r"(?:^|/)(?:\.streamlit|\.gpt-pilot|\.aider|\.cursor"
            r"|\.windsurf|\.copilot|\.devcontainer)(?:/|$)",
            _CTX_RECON,
            "recon",
        ),
        (
            r"(?:^|/)(?:docker-compose|Dockerfile|Makefile|Vagrantfile"
            r"|Jenkinsfile|Procfile)(?:\.ya?ml)?(?:\?|$)",
            _CTX_RECON,
            "recon",
        ),
        (
            r"(?:^|/)[\w./-]*(?:secrets?|credentials?)"
            r"\.(?:py|json|yml|yaml|toml|txt|env|xml|conf|cfg)(?:\?|$)",
            _CTX_RECON,
            "recon",
        ),
        (r"(?:^|/)autodiscover/", _CTX_RECON, "recon"),
        (r"^/dns-query(?:\?|$)", _CTX_RECON, "recon"),
        (r"(?:^|/)\.git/(?:refs|index|HEAD|objects|logs)(?:/|$)", _CTX_RECON, "recon"),
    ]

    patterns: list[str] = [p[0] for p in _pattern_definitions]

    custom_patterns: set[str]
    compiled_patterns: list[tuple[re.Pattern, frozenset[str], str]]
    compiled_custom_patterns: set[tuple[re.Pattern, frozenset[str], str]]
    redis_handler: Any
    agent_handler: Any
    _compiler: PatternCompiler | None
    _preprocessor: ContentPreprocessor | None
    _semantic_analyzer: SemanticAnalyzer | None
    _performance_monitor: PerformanceMonitor | None
    _semantic_threshold: float

    def __new__(
        cls: type["SusPatternsManager"], config: Any = None
    ) -> "SusPatternsManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.custom_patterns = set()
            cls._instance.compiled_patterns = [
                (re.compile(pattern, re.IGNORECASE | re.MULTILINE), contexts, category)
                for pattern, contexts, category in cls._pattern_definitions
            ]
            cls._instance.compiled_custom_patterns = set()
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None

            cls._config = config

            if config and hasattr(config, "detection_compiler_timeout"):
                cls._instance._compiler = PatternCompiler(
                    default_timeout=config.detection_compiler_timeout,
                    max_cache_size=config.detection_max_tracked_patterns,
                )
                cls._instance._preprocessor = ContentPreprocessor(
                    max_content_length=config.detection_max_content_length,
                    preserve_attack_patterns=config.detection_preserve_attack_patterns,
                )
                cls._instance._semantic_analyzer = SemanticAnalyzer()
                cls._instance._performance_monitor = PerformanceMonitor(
                    anomaly_threshold=config.detection_anomaly_threshold,
                    slow_pattern_threshold=config.detection_slow_pattern_threshold,
                    history_size=config.detection_monitor_history_size,
                    max_tracked_patterns=config.detection_max_tracked_patterns,
                )
                cls._instance._semantic_threshold = config.detection_semantic_threshold
            else:
                cls._instance._compiler = None
                cls._instance._preprocessor = None
                cls._instance._semantic_analyzer = None
                cls._instance._performance_monitor = None
                cls._instance._semantic_threshold = 0.7

        return cls._instance

    async def initialize_redis(self, redis_handler: Any) -> None:
        self.redis_handler = redis_handler
        if self.redis_handler:
            cached_patterns = await self.redis_handler.get_key("patterns", "custom")
            if cached_patterns:
                patterns = cached_patterns.split(",")
                for pattern in patterns:
                    if pattern not in self.custom_patterns:
                        await self.add_pattern(pattern, custom=True)

    async def initialize_agent(self, agent_handler: Any) -> None:
        self.agent_handler = agent_handler

    async def _send_pattern_event(
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
            await self.agent_handler.send_event(event)
        except Exception as e:
            import logging

            logging.getLogger("guard_core.handlers.suspatterns").error(
                f"Failed to send pattern event to agent: {e}"
            )

    async def _preprocess_content(
        self, content: str, correlation_id: str | None
    ) -> str:
        if not self._preprocessor:
            return content

        context_preprocessor = ContentPreprocessor(
            max_content_length=self._preprocessor.max_content_length,
            preserve_attack_patterns=self._preprocessor.preserve_attack_patterns,
            agent_handler=self.agent_handler,
            correlation_id=correlation_id,
        )
        return await context_preprocessor.preprocess(content)

    async def _check_regex_pattern(
        self,
        pattern: re.Pattern,
        content: str,
        ip_address: str,
        pattern_start: float,
        category: str,
    ) -> tuple[dict | None, bool]:
        timeout_occurred = False

        if self._compiler:
            safe_matcher = self._compiler.create_safe_matcher(pattern.pattern)
            match = safe_matcher(content)

            if match is None and time.time() - pattern_start >= 0.9 * 2.0:
                timeout_occurred = True
                import logging

                logging.getLogger("guard_core.handlers.suspatterns").warning(
                    f"Pattern timeout: {pattern.pattern[:50]}..."
                )
            elif match:
                return {
                    "type": "regex",
                    "pattern": pattern.pattern,
                    "match": match.group(),
                    "position": match.start(),
                    "execution_time": time.time() - pattern_start,
                    "category": category,
                }, timeout_occurred
        else:
            match, timeout_occurred = await self._check_pattern_with_timeout(
                pattern, content, ip_address, pattern_start
            )
            if match:
                return {
                    "type": "regex",
                    "pattern": pattern.pattern,
                    "match": match.group(),
                    "position": match.start(),
                    "execution_time": time.time() - pattern_start,
                    "category": category,
                }, timeout_occurred

        return None, timeout_occurred

    async def _check_pattern_with_timeout(
        self, pattern: re.Pattern, content: str, ip_address: str, pattern_start: float
    ) -> tuple[re.Match | None, bool]:
        import concurrent.futures

        def _search(p: re.Pattern = pattern) -> re.Match | None:
            return p.search(content)

        executor_class = concurrent.futures.ThreadPoolExecutor
        with executor_class(max_workers=1) as executor:
            future = executor.submit(_search)
            try:
                match = future.result(timeout=2.0)
                return match, False
            except concurrent.futures.TimeoutError:
                import logging

                logger = logging.getLogger("guard_core.handlers.suspatterns")
                logger.warning(
                    f"Regex timeout exceeded for pattern: "
                    f"{pattern.pattern[:50]}... "
                    f"Potential ReDoS attack blocked. IP: {ip_address}"
                )
                future.cancel()
                return None, True
            except Exception as e:
                import logging

                logger = logging.getLogger("guard_core.handlers.suspatterns")
                logger.error(
                    f"Error in regex search for pattern {pattern.pattern[:50]}...: {e}"
                )
                return None, False

    _KNOWN_CONTEXTS = frozenset(
        {"query_param", "header", "url_path", "request_body", "unknown"}
    )

    @staticmethod
    def _normalize_context(context: str) -> str:
        normalized = context.split(":", 1)[0]
        if normalized not in SusPatternsManager._KNOWN_CONTEXTS:
            return "unknown"
        return normalized

    async def _check_regex_patterns(
        self,
        content: str,
        ip_address: str,
        correlation_id: str | None,
        context: str = "unknown",
        enabled_categories: set[str] | None = None,
    ) -> tuple[list[dict], list[str], list[str]]:
        threats = []
        matched_patterns = []
        timeouts = []

        all_patterns = await self.get_all_compiled_patterns()
        normalized = self._normalize_context(context)
        skip_filter = normalized in ("unknown", "request_body")

        for pattern, contexts, category in all_patterns:
            if not skip_filter and normalized not in contexts:
                continue
            if (
                enabled_categories is not None
                and category != "custom"
                and category not in enabled_categories
            ):
                continue

            pattern_start = time.time()

            threat, timeout_occurred = await self._check_regex_pattern(
                pattern, content, ip_address, pattern_start, category
            )

            if timeout_occurred:
                timeouts.append(pattern.pattern)

            if threat:
                threats.append(threat)
                matched_patterns.append(pattern.pattern)

            if self._performance_monitor:
                await self._performance_monitor.record_metric(
                    pattern=pattern.pattern,
                    execution_time=time.time() - pattern_start,
                    content_length=len(content),
                    matched=bool(threat),
                    timeout=timeout_occurred,
                    agent_handler=self.agent_handler,
                    correlation_id=correlation_id,
                )

        return threats, matched_patterns, timeouts

    async def _check_semantic_threats(self, content: str) -> tuple[list[dict], float]:
        if not self._semantic_analyzer:
            return [], 0.0

        semantic_analysis = self._semantic_analyzer.analyze(content)
        semantic_score = self._semantic_analyzer.get_threat_score(semantic_analysis)
        threats = []

        if semantic_score > self._semantic_threshold:
            attack_probs = semantic_analysis.get("attack_probabilities", {})

            for attack_type, probability in attack_probs.items():
                if probability >= self._semantic_threshold:
                    threats.append(
                        {
                            "type": "semantic",
                            "attack_type": attack_type,
                            "probability": probability,
                            "analysis": semantic_analysis,
                        }
                    )

            if not threats and semantic_score >= self._semantic_threshold:
                threats.append(
                    {
                        "type": "semantic",
                        "attack_type": "suspicious",
                        "threat_score": semantic_score,
                        "analysis": semantic_analysis,
                    }
                )

        return threats, semantic_score

    async def _calculate_threat_score(
        self, regex_threats: list, semantic_threats: list
    ) -> float:
        if not (regex_threats or semantic_threats):
            return 0.0

        regex_score = 1.0 if regex_threats else 0.0
        semantic_scores = [
            t.get("probability", t.get("threat_score", 0.0)) for t in semantic_threats
        ]
        semantic_max = max(semantic_scores) if semantic_scores else 0.0
        return max(regex_score, semantic_max)

    async def detect(
        self,
        content: str,
        ip_address: str,
        context: str = "unknown",
        correlation_id: str | None = None,
        enabled_categories: set[str] | None = None,
    ) -> dict[str, Any]:
        original_content = content
        execution_start = time.time()

        processed_content = await self._preprocess_content(content, correlation_id)

        regex_threats, matched_patterns, timeouts = await self._check_regex_patterns(
            processed_content,
            ip_address,
            correlation_id,
            context,
            enabled_categories,
        )

        semantic_threats, semantic_score = await self._check_semantic_threats(
            processed_content
        )

        threats = regex_threats + semantic_threats
        is_threat = len(threats) > 0

        threat_score = await self._calculate_threat_score(
            regex_threats, semantic_threats
        )

        total_execution_time = time.time() - execution_start

        if self._performance_monitor:
            await self._performance_monitor.record_metric(
                pattern="overall_detection",
                execution_time=total_execution_time,
                content_length=len(content),
                matched=is_threat,
                timeout=False,
                agent_handler=self.agent_handler,
                correlation_id=correlation_id,
            )

        if is_threat:
            await self._send_threat_event(
                matched_patterns,
                semantic_threats,
                ip_address,
                context,
                content,
                threat_score,
                threats,
                regex_threats,
                timeouts,
                total_execution_time,
                correlation_id,
            )

        return {
            "is_threat": is_threat,
            "threat_score": threat_score,
            "threats": threats,
            "context": context,
            "original_length": len(original_content),
            "processed_length": len(processed_content),
            "execution_time": total_execution_time,
            "detection_method": "enhanced" if self._compiler else "legacy",
            "timeouts": timeouts,
            "correlation_id": correlation_id,
        }

    async def _send_threat_event(
        self,
        matched_patterns: list,
        semantic_threats: list,
        ip_address: str,
        context: str,
        content: str,
        threat_score: float,
        threats: list,
        regex_threats: list,
        timeouts: list,
        execution_time: float,
        correlation_id: str | None,
    ) -> None:
        from guard_core.core.events.event_types import EVENT_PATTERN_DETECTED

        pattern_info = "unknown"
        if matched_patterns:
            pattern_info = matched_patterns[0]
        elif semantic_threats:
            pattern_info = f"semantic:{semantic_threats[0]['attack_type']}"

        await self._send_pattern_event(
            event_type=EVENT_PATTERN_DETECTED,
            ip_address=ip_address,
            action_taken="threat_detected",
            reason=f"Threat detected in {context}",
            pattern=pattern_info,
            context=context,
            content_preview=content[:100] if len(content) > 100 else content,
            threat_score=threat_score,
            threats=len(threats),
            regex_threats=len(regex_threats),
            semantic_threats=len(semantic_threats),
            timeouts=len(timeouts),
            detection_method="enhanced" if self._compiler else "legacy",
            execution_time_ms=int(execution_time * 1000),
            correlation_id=correlation_id,
        )

    async def detect_pattern_match(
        self,
        content: str,
        ip_address: str,
        context: str = "unknown",
        correlation_id: str | None = None,
    ) -> tuple[bool, str | None]:
        result = await self.detect(content, ip_address, context, correlation_id)

        if result["is_threat"]:
            if result["threats"]:
                threat = result["threats"][0]
                if threat["type"] == "regex":
                    return True, threat["pattern"]
                elif threat["type"] == "semantic":
                    return True, f"semantic:{threat.get('attack_type', 'suspicious')}"
            return True, "unknown"

        return False, None

    @classmethod
    async def add_pattern(cls, pattern: str, custom: bool = False) -> None:
        instance = cls()

        compiled_pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        compiled_tuple = (compiled_pattern, _CTX_ALL, "custom")
        if custom:
            instance.compiled_custom_patterns.add(compiled_tuple)
            instance.custom_patterns.add(pattern)

            if instance.redis_handler:
                await instance.redis_handler.set_key(
                    "patterns", "custom", ",".join(instance.custom_patterns)
                )
        else:
            instance.compiled_patterns.append(compiled_tuple)
            instance.patterns.append(pattern)

        if instance._compiler:
            await instance._compiler.clear_cache()

        if instance.agent_handler:
            details = f"{'Custom' if custom else 'Default'} pattern added"
            await instance._send_pattern_event(
                event_type="pattern_added",
                ip_address="system",
                action_taken="pattern_added",
                reason=f"{details} to detection system",
                pattern=pattern,
                pattern_type="custom" if custom else "default",
                total_patterns=len(instance.custom_patterns)
                if custom
                else len(instance.patterns),
            )

    async def _remove_custom_pattern(self, pattern: str) -> bool:
        if pattern not in self.custom_patterns:
            return False

        self.custom_patterns.discard(pattern)

        self.compiled_custom_patterns = {
            (p, ctx, cat)
            for p, ctx, cat in self.compiled_custom_patterns
            if p.pattern != pattern
        }

        if self.redis_handler:
            await self.redis_handler.set_key(
                "patterns", "custom", ",".join(self.custom_patterns)
            )

        return True

    async def _remove_default_pattern(self, pattern: str) -> bool:
        if pattern not in self.patterns:
            return False

        index = self.patterns.index(pattern)
        self.patterns.pop(index)

        if 0 <= index < len(self.compiled_patterns):
            self.compiled_patterns.pop(index)
            return True

        return False

    async def _clear_pattern_caches(self, pattern: str) -> None:
        if self._compiler:
            await self._compiler.clear_cache()
        if self._performance_monitor:
            await self._performance_monitor.remove_pattern_stats(pattern)

    async def _send_pattern_removal_event(
        self, pattern: str, custom: bool, total_patterns: int
    ) -> None:
        if not self.agent_handler:
            return

        details = f"{'Custom' if custom else 'Default'} pattern removed"
        await self._send_pattern_event(
            event_type="pattern_removed",
            ip_address="system",
            action_taken="pattern_removed",
            reason=f"{details} from detection system",
            pattern=pattern,
            pattern_type="custom" if custom else "default",
            total_patterns=total_patterns,
        )

    @classmethod
    async def remove_pattern(cls, pattern: str, custom: bool = False) -> bool:
        instance = cls()

        if custom:
            pattern_removed = await instance._remove_custom_pattern(pattern)
        else:
            pattern_removed = await instance._remove_default_pattern(pattern)

        if pattern_removed:
            await instance._clear_pattern_caches(pattern)

        if pattern_removed:
            total_patterns = (
                len(instance.custom_patterns) if custom else len(instance.patterns)
            )
            await instance._send_pattern_removal_event(pattern, custom, total_patterns)

        return pattern_removed

    @classmethod
    async def get_default_patterns(cls) -> list[str]:
        instance = cls()
        return instance.patterns.copy()

    @classmethod
    async def get_custom_patterns(cls) -> list[str]:
        instance = cls()
        return list(instance.custom_patterns)

    @classmethod
    async def get_all_patterns(cls) -> list[str]:
        instance = cls()
        return instance.patterns + list(instance.custom_patterns)

    @classmethod
    async def get_default_compiled_patterns(
        cls,
    ) -> list[tuple[re.Pattern, frozenset[str], str]]:
        instance = cls()
        return instance.compiled_patterns.copy()

    @classmethod
    async def get_custom_compiled_patterns(
        cls,
    ) -> list[tuple[re.Pattern, frozenset[str], str]]:
        instance = cls()
        return list(instance.compiled_custom_patterns)

    @classmethod
    async def get_all_compiled_patterns(
        cls,
    ) -> list[tuple[re.Pattern, frozenset[str], str]]:
        instance = cls()
        return instance.compiled_patterns + list(instance.compiled_custom_patterns)

    @classmethod
    async def get_performance_stats(cls) -> dict[str, Any] | None:
        instance = cls()
        if instance._performance_monitor:
            return {
                "summary": instance._performance_monitor.get_summary_stats(),
                "slow_patterns": instance._performance_monitor.get_slow_patterns(),
                "problematic_patterns": (
                    instance._performance_monitor.get_problematic_patterns()
                ),
            }
        return None

    @classmethod
    async def get_component_status(cls) -> dict[str, bool]:
        instance = cls()
        return {
            "compiler": instance._compiler is not None,
            "preprocessor": instance._preprocessor is not None,
            "semantic_analyzer": instance._semantic_analyzer is not None,
            "performance_monitor": instance._performance_monitor is not None,
        }

    async def configure_semantic_threshold(self, threshold: float) -> None:
        self._semantic_threshold = max(0.0, min(1.0, threshold))

    @classmethod
    async def reset(cls) -> None:
        if cls._instance is not None:
            cls._instance.custom_patterns.clear()
            cls._instance.compiled_custom_patterns.clear()

            cls._instance.redis_handler = None
            cls._instance.agent_handler = None

            if hasattr(cls._instance, "_compiler") and cls._instance._compiler:
                await cls._instance._compiler.clear_cache()

            if (
                hasattr(cls._instance, "_performance_monitor")
                and cls._instance._performance_monitor
            ):
                cls._instance._performance_monitor.pattern_stats.clear()
                cls._instance._performance_monitor.recent_metrics.clear()

            cls._config = None


sus_patterns_handler = SusPatternsManager()
