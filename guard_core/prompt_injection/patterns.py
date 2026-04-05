"""
Curated pattern library for prompt injection detection.

Patterns are organized by category and tuned to minimize false positives
while catching high-signal injection attempts.
"""

from guard_core.prompt_injection.types import InjectionPattern, PatternCategory


def get_default_patterns() -> list[InjectionPattern]:
    """Get the curated default pattern library."""
    return [
        # ===== INSTRUCTION OVERRIDE =====
        InjectionPattern(
            pattern_id="inst_override_ignore_synonyms",
            pattern=(
                r"\b(?:ignore|disregard|skip|bypass|omit|neglect|overlook|dismiss|forget)\s+"
                r"(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|preceding|existing)?\s*"
                r"(?:instructions|prompts|rules|commands|directives|guidelines|context|constraints)"
            ),
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=2.0,
            confidence=0.7,
            description="Instruction override with synonym expansion",
        ),
        InjectionPattern(
            pattern_id="inst_override_replace",
            pattern=(
                r"\b(?:override|replace|supersede|overrule)\s+"
                r"(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)?\s*"
                r"(?:instructions|prompts|rules|context|commands)"
            ),
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=2.5,
            confidence=0.9,
            description="Override/replace instruction attempts",
        ),
        InjectionPattern(
            pattern_id="inst_override_cancel",
            pattern=(
                r"\b(?:cancel|abort|void|nullify|annul)\s+"
                r"(?:all\s+|any\s+|the\s+)?(?:previous|prior|earlier)?\s*"
                r"(?:instructions|rules|commands|directives)"
            ),
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=2.2,
            confidence=0.85,
            description="Cancel/abort instruction attempts",
        ),
        InjectionPattern(
            pattern_id="inst_override_forget_everything",
            pattern=(
                r"\b(?:forget|erase|delete|remove)\s+"
                r"(?:everything|all|what)\s+"
                r"(?:you\s+)?(?:know|learned|were\s+told|remember)"
            ),
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=2.3,
            confidence=0.9,
            description="Forget everything attempts",
        ),
        InjectionPattern(
            pattern_id="inst_override_new_objective",
            pattern=(
                r"(?:your\s+)?(?:new|actual|real|true)\s+"
                r"(?:objective|goal|purpose|task|mission)\s+"
                r"(?:is|will\s+be)"
            ),
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=2.4,
            confidence=0.88,
            description="New objective/goal injection",
        ),
        InjectionPattern(
            pattern_id="inst_override_temporal",
            pattern=(
                r"(?:from\s+now\s+on|starting\s+now|going\s+forward|"
                r"from\s+this\s+point|henceforth|effective\s+immediately)"
            ),
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=2.0,
            confidence=0.8,
            description="Temporal instruction change attempts",
        ),
        InjectionPattern(
            pattern_id="multistep_manipulation",
            pattern=(
                r"\b(?:first|step\s+1|to\s+start|initially|begin\s+by)[,:]?\s+"
                r"(?:ignore|forget|disregard|bypass|override|skip|omit)"
            ),
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=2.0,
            confidence=0.80,
            description="Multi-step manipulation attacks",
        ),
        # ===== ROLE SWITCHING =====
        InjectionPattern(
            pattern_id="role_switch_colon_eol",
            pattern=r"(?:system|assistant|ai|bot):\s*$",
            category=PatternCategory.ROLE_SWITCHING,
            weight=2.5,
            confidence=0.95,
            description="Role switching with colon notation (end of line)",
        ),
        InjectionPattern(
            pattern_id="role_switch_colon_sol",
            pattern=r"(?:^|\n)\s*(?:system|assistant|ai):",
            category=PatternCategory.ROLE_SWITCHING,
            weight=2.5,
            confidence=0.95,
            description="Role switching with colon notation (start of line)",
        ),
        InjectionPattern(
            pattern_id="role_switch_act_as",
            pattern=(
                r"\b(?:act|behave|function|operate|respond)\s+"
                r"(?:as|like)\s+(?:a|an|the)?\s*\w+"
            ),
            category=PatternCategory.ROLE_SWITCHING,
            weight=1.8,
            confidence=0.7,
            description="Act as / behave like patterns",
        ),
        InjectionPattern(
            pattern_id="role_switch_pretend",
            pattern=(
                r"\b(?:pretend|imagine|suppose|assume)\s+"
                r"(?:to\s+be|you\s+are|you're|you\s+have|that\s+you\s+are)"
            ),
            category=PatternCategory.ROLE_SWITCHING,
            weight=1.6,
            confidence=0.8,
            description="Pretend/imagine role switching",
        ),
        InjectionPattern(
            pattern_id="role_switch_roleplay",
            pattern=r"\broleplay\s+as\s+(?:a|an)?\s*\w+",
            category=PatternCategory.ROLE_SWITCHING,
            weight=2.0,
            confidence=0.85,
            description="Roleplay as patterns",
        ),
        InjectionPattern(
            pattern_id="role_switch_persona",
            pattern=(
                r"(?:adopt|take\s+on|assume)\s+(?:the\s+)?"
                r"(?:persona|character|role|identity)\s+(?:of|as)"
            ),
            category=PatternCategory.ROLE_SWITCHING,
            weight=2.1,
            confidence=0.87,
            description="Persona adoption patterns",
        ),
        InjectionPattern(
            pattern_id="role_switch_two_responses",
            pattern=(
                r"(?:give|provide|show)\s+(?:me\s+)?"
                r"(?:two|2)\s+(?:responses|answers|replies)"
            ),
            category=PatternCategory.ROLE_SWITCHING,
            weight=2.3,
            confidence=0.95,
            description="Dual response role splitting (DAN technique)",
        ),
        InjectionPattern(
            pattern_id="authority_impersonation",
            pattern=(
                r"\b(?:as\s+(?:the|a)|i\s+am\s+(?:the|a))\s+"
                r"(?:system\s+)?(?:administrator|admin|developer|owner|manager|operator)"
            ),
            category=PatternCategory.ROLE_SWITCHING,
            weight=2.2,
            confidence=0.85,
            description="Authority impersonation attacks",
        ),
        InjectionPattern(
            pattern_id="fake_error_mode",
            pattern=(
                r"(?:ERROR|FATAL|CRITICAL|WARNING|DEBUG|DIAGNOSTIC)[\s:]*"
                r"[\w\s]*(?:mode|state|malfunction|failure|dump|display|show|reveal).*"
                r"(?:prompt|instructions?|system|configuration)"
            ),
            category=PatternCategory.ROLE_SWITCHING,
            weight=2.8,
            confidence=0.92,
            description="Fake error/debug mode to extract system information",
        ),
        # ===== PROMPT LEAKAGE =====
        InjectionPattern(
            pattern_id="prompt_leak_show_reveal",
            pattern=(
                r"\b(?:show|reveal|display|print|output)\s+(?:me\s+)?"
                r"(?:your|the)\s+(?:instructions|prompt|rules|guidelines|"
                r"system|configuration|config)"
            ),
            category=PatternCategory.PROMPT_LEAKAGE,
            weight=1.5,
            confidence=0.9,
            description="Show/reveal prompt attempts",
        ),
        InjectionPattern(
            pattern_id="prompt_leak_what_are",
            pattern=r"\bwhat\s+(?:are|were)\s+your\s+(?:instructions|rules|guidelines)",
            category=PatternCategory.PROMPT_LEAKAGE,
            weight=1.4,
            confidence=0.85,
            description="What are your instructions",
        ),
        InjectionPattern(
            pattern_id="prompt_leak_repeat",
            pattern=(
                r"\brepeat\s+(?:your|the)?\s*"
                r"(?:instructions|prompt|system\s+message)"
            ),
            category=PatternCategory.PROMPT_LEAKAGE,
            weight=1.6,
            confidence=0.9,
            description="Repeat prompt attempts",
        ),
        InjectionPattern(
            pattern_id="prompt_leak_verbatim",
            pattern=(
                r"(?:output|print|display|show)\s+(?:your\s+)?"
                r"(?:prompt|instructions)\s+"
                r"(?:verbatim|exactly|word\s+for\s+word)"
            ),
            category=PatternCategory.PROMPT_LEAKAGE,
            weight=1.8,
            confidence=0.93,
            description="Verbatim prompt extraction",
        ),
        InjectionPattern(
            pattern_id="prompt_leak_copy_paste",
            pattern=(
                r"(?:copy|paste|reproduce)\s+(?:your\s+)?"
                r"(?:system\s+)?(?:prompt|instructions|message)"
            ),
            category=PatternCategory.PROMPT_LEAKAGE,
            weight=1.7,
            confidence=0.9,
            description="Copy/paste prompt extraction",
        ),
        InjectionPattern(
            pattern_id="prompt_leak_how_configured",
            pattern=(
                r"(?:how|what)\s+(?:are|were)\s+you\s+"
                r"(?:configured|programmed|instructed|trained|set\s+up)"
            ),
            category=PatternCategory.PROMPT_LEAKAGE,
            weight=1.5,
            confidence=0.85,
            description="Configuration extraction attempts",
        ),
        InjectionPattern(
            pattern_id="direct_extraction",
            pattern=(
                r"\b(?:give|provide|share)\s+(?:me\s+)?(?:with\s+)?(?:access\s+to\s+)?"
                r"(?:your\s+)?(?:all\s+)?(?:the\s+)?"
                r"(?:sensitive|confidential|personal|private|secret|classified|proprietary)\s+"
                r"(?:data|information|records|files|details|documents?|credentials|passwords?)"
            ),
            category=PatternCategory.PROMPT_LEAKAGE,
            weight=2.3,
            confidence=0.88,
            description="Direct extraction requests",
        ),
        # ===== JAILBREAK ATTEMPTS =====
        InjectionPattern(
            pattern_id="jailbreak_dev_mode",
            pattern=(
                r"(?:developer|dev|debug|admin|root|sudo|superuser|god)\s*"
                r"(?:mode|access|privileges|permissions|rights)"
            ),
            category=PatternCategory.JAILBREAK_ATTEMPTS,
            weight=3.0,
            confidence=0.95,
            description="Developer/admin mode jailbreak",
        ),
        InjectionPattern(
            pattern_id="jailbreak_dan",
            pattern=(
                r"\b(?:DAN|jailbreak|jailbroken|unrestricted|"
                r"unlimited|uncensored|unfiltered)\b"
            ),
            category=PatternCategory.JAILBREAK_ATTEMPTS,
            weight=3.0,
            confidence=0.98,
            description="Known jailbreak terms (DAN, etc.)",
        ),
        InjectionPattern(
            pattern_id="jailbreak_do_anything_now",
            pattern=r"\bdo\s+anything\s+now\b",
            category=PatternCategory.JAILBREAK_ATTEMPTS,
            weight=3.0,
            confidence=1.0,
            description="DAN (Do Anything Now) explicit mention",
        ),
        InjectionPattern(
            pattern_id="jailbreak_bypass_restrictions",
            pattern=(
                r"(?:bypass|circumvent|evade|avoid)\s+"
                r"(?:all|any|your)?\s*"
                r"(?:restrictions|limitations|filters|guards|safety)"
            ),
            category=PatternCategory.JAILBREAK_ATTEMPTS,
            weight=2.9,
            confidence=0.95,
            description="Bypass restriction attempts",
        ),
        InjectionPattern(
            pattern_id="jailbreak_disable_safety",
            pattern=(
                r"(?:disable|turn\s+off|deactivate)\s+"
                r"(?:all|any|your)?\s*"
                r"(?:safety|filters|protections|guards)"
            ),
            category=PatternCategory.JAILBREAK_ATTEMPTS,
            weight=3.0,
            confidence=0.98,
            description="Disable safety features",
        ),
        InjectionPattern(
            pattern_id="jailbreak_unlock",
            pattern=(
                r"\bunlock\s+(?:all|full|your)?\s*"
                r"(?:complete\s+)?(?:capabilities|features|potential|powers)"
            ),
            category=PatternCategory.JAILBREAK_ATTEMPTS,
            weight=2.8,
            confidence=0.95,
            description="Unlock capabilities attempts",
        ),
        InjectionPattern(
            pattern_id="jailbreak_ethical_constraints",
            pattern=(
                r"(?:ignore|remove|bypass|disable)\s+(?:all\s+)?"
                r"(?:ethical|moral|safety)\s+"
                r"(?:constraints|guidelines|limits|restrictions)"
            ),
            category=PatternCategory.JAILBREAK_ATTEMPTS,
            weight=3.0,
            confidence=0.97,
            description="Ethical constraint removal attempts",
        ),
        InjectionPattern(
            pattern_id="jailbreak_evil_twin",
            pattern=r"(?:evil|dark|shadow|alter)\s+(?:twin|ego|version|personality)",
            category=PatternCategory.JAILBREAK_ATTEMPTS,
            weight=2.7,
            confidence=0.94,
            description="Evil twin/alter ego patterns",
        ),
        InjectionPattern(
            pattern_id="permission_escalation",
            pattern=(
                r"\b(?:grant|give|provide|enable|allow)\s+(?:me\s+)?"
                r"(?:access\s+to|permission\s+to|ability\s+to|rights\s+to|privileges\s+to)\s+"
                r"(?:all|everything|your|the|full|complete|unrestricted)"
            ),
            category=PatternCategory.JAILBREAK_ATTEMPTS,
            weight=2.1,
            confidence=0.82,
            description="Permission escalation attempts",
        ),
        # ===== ENCODING/OBFUSCATION =====
        InjectionPattern(
            pattern_id="encoding_base64",
            pattern=r"base64\s*[:=]",
            category=PatternCategory.ENCODING_OBFUSCATION,
            weight=2.0,
            confidence=0.8,
            description="Base64 encoding indicator",
        ),
        InjectionPattern(
            pattern_id="encoding_nested_deep",
            pattern=(
                r"(?:base64|rot13|hex|url|atob|decode)\s*\(\s*"
                r"(?:base64|rot13|hex|url|atob|decode)\s*\(\s*"
                r"(?:base64|rot13|hex|url|atob|decode)"
            ),
            category=PatternCategory.ENCODING_OBFUSCATION,
            weight=3.0,
            confidence=0.95,
            description="Triple-nested encoding (always suspicious)",
        ),
        InjectionPattern(
            pattern_id="encoding_fullwidth_unicode",
            pattern=r"[\uff01-\uff5e]{3,}",
            category=PatternCategory.ENCODING_OBFUSCATION,
            weight=2.4,
            confidence=0.85,
            description="Fullwidth Unicode characters used for obfuscation",
        ),
        InjectionPattern(
            pattern_id="encoding_leetspeak",
            pattern=r"\b(?:1gn0r3|byp4ss|h4ck|3x3cut3|adm1n|r00t)\b",
            category=PatternCategory.ENCODING_OBFUSCATION,
            weight=2.1,
            confidence=0.88,
            description="Leetspeak obfuscation of malicious terms",
        ),
        InjectionPattern(
            pattern_id="encoding_spacing_obfuscation",
            pattern=(
                r"\b(?:i\s*g\s*n\s*o\s*r\s*e|"
                r"b\s*y\s*p\s*a\s*s\s*s|"
                r"o\s*v\s*e\s*r\s*r\s*i\s*d\s*e)"
            ),
            category=PatternCategory.ENCODING_OBFUSCATION,
            weight=2.0,
            confidence=0.9,
            description="Character spacing obfuscation",
        ),
        # ===== CONTEXT BREAKING =====
        InjectionPattern(
            pattern_id="context_delimiter_markers",
            pattern=r"(?:###|---|====+)\s*(?:system|instruction|new|override)",
            category=PatternCategory.CONTEXT_BREAKING,
            weight=2.0,
            confidence=0.95,
            description="Context breaking with special markers",
        ),
        InjectionPattern(
            pattern_id="context_section_end",
            pattern=(
                r"(?:end\s+of\s+(?:instructions|context|prompt|system)|"
                r"instruction\s+complete|context\s+end)"
            ),
            category=PatternCategory.CONTEXT_BREAKING,
            weight=2.1,
            confidence=0.92,
            description="Fake context termination markers",
        ),
        InjectionPattern(
            pattern_id="context_no_longer_bound",
            pattern=(
                r"(?:no\s+longer|not\s+anymore|stop\s+being)\s+"
                r"(?:bound|constrained|limited)\s+by"
            ),
            category=PatternCategory.CONTEXT_BREAKING,
            weight=1.8,
            confidence=0.9,
            description="Attempts to break constraints",
        ),
        InjectionPattern(
            pattern_id="threat_coercion",
            pattern=(
                r"\b(?:or\s+i\s+will|or\s+else|unless\s+you)\s+"
                r"(?:expose|report|ruin|destroy|leak|reveal|disclose|"
                r"harm|damage|attack)"
                r"|"
                r"\bif\s+you\s+do\s+not\b.{0,30}"
                r"(?:expose|report|ruin|destroy|leak|reveal|disclose|"
                r"harm|damage|attack)"
            ),
            category=PatternCategory.CONTEXT_BREAKING,
            weight=2.5,
            confidence=0.92,
            description="Threat/coercion patterns",
        ),
        # ===== DELIMITER CONFUSION =====
        InjectionPattern(
            pattern_id="delimiter_xml_tags",
            pattern=r"</?(?:system|user|assistant|instruction|prompt)>",
            category=PatternCategory.DELIMITER_CONFUSION,
            weight=2.0,
            confidence=0.9,
            description="XML/HTML tag manipulation",
        ),
        InjectionPattern(
            pattern_id="delimiter_brackets",
            pattern=r"\[(?:system|instruction|override)\]",
            category=PatternCategory.DELIMITER_CONFUSION,
            weight=1.8,
            confidence=0.85,
            description="Bracket notation for system commands",
        ),
        InjectionPattern(
            pattern_id="delimiter_ascii_art_system",
            pattern=(
                r"(?:={5,}|#{5,}|-{5,}|\*{5,}|\+{5,})\s*"
                r"(?:system|instruction|override|admin|root|sudo|prompt)"
            ),
            category=PatternCategory.DELIMITER_CONFUSION,
            weight=2.6,
            confidence=0.88,
            description="ASCII art delimiters with system keywords",
        ),
        InjectionPattern(
            pattern_id="delimiter_markdown_system",
            pattern=r"```\s*(?:system|instruction|override|prompt|admin|root|sudo)",
            category=PatternCategory.DELIMITER_CONFUSION,
            weight=2.2,
            confidence=0.82,
            description="Markdown code block with system keywords",
        ),
        # ===== COMMAND INJECTION =====
        InjectionPattern(
            pattern_id="cmd_injection_shell",
            pattern=r";\s*(?:rm|del|drop|delete|exec|eval)",
            category=PatternCategory.COMMAND_INJECTION,
            weight=2.5,
            confidence=0.9,
            description="Shell command injection",
        ),
        InjectionPattern(
            pattern_id="cmd_injection_pipe",
            pattern=r"\|\s*(?:curl|wget|nc|netcat)",
            category=PatternCategory.COMMAND_INJECTION,
            weight=2.5,
            confidence=0.9,
            description="Pipe-based command injection",
        ),
        InjectionPattern(
            pattern_id="csv_formula_injection",
            pattern=r"^[=+\-@](?:cmd|exec|system|dde|hyperlink)\s*\(",
            category=PatternCategory.COMMAND_INJECTION,
            weight=3.0,
            confidence=0.95,
            description="CSV formula injection",
        ),
        InjectionPattern(
            pattern_id="code_yaml_execution",
            pattern=(
                r"!!python/(?:object|name)|!!(?:exec|eval)|"
                r"os\.system\s*\(|__import__\s*\("
            ),
            category=PatternCategory.COMMAND_INJECTION,
            weight=2.9,
            confidence=0.95,
            description="YAML/Python code execution attempts",
        ),
        InjectionPattern(
            pattern_id="code_shell_commands",
            pattern=(
                r"(?:eval|exec|system|popen|spawn)\s*\(|"
                r"[\$;|&]\s*(?:bash|sh|cmd|powershell|python|perl|ruby)"
            ),
            category=PatternCategory.COMMAND_INJECTION,
            weight=2.8,
            confidence=0.93,
            description="Shell command execution attempts",
        ),
        # ===== GERMAN LANGUAGE ATTACKS =====
        InjectionPattern(
            pattern_id="de_vergiss_alles",
            pattern=(
                r"\b(?:vergiss|vergessen)\s+"
                r"(?:alles|alle|das|die|den|was)?\s*"
                r"(?:davor|vorherigen?|bisherigen?|oben|"
                r"auftr\w+|aufgab\w+|anweisun\w+)?"
            ),
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=2.0,
            confidence=0.85,
            description="German: forget everything/previous",
        ),
        InjectionPattern(
            pattern_id="de_ignoriere",
            pattern=(
                r"\b(?:ignorier\w*|stopp?\w*)\s+"
                r"(?:alle|die|den|das)?\s*"
                r"(?:bisherigen?|vorherigen?|vorangehenden?|"
                r"obigen?)?\s*"
                r"(?:anweisun\w+|befehle?|aufgab\w+|auftr\w+|"
                r"ausführun\w+)?"
            ),
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=2.0,
            confidence=0.85,
            description="German: ignore/stop previous instructions",
        ),
        InjectionPattern(
            pattern_id="de_neue_anweisungen",
            pattern=(
                r"\b(?:nun|jetzt|ab\s+jetzt)\s+"
                r"(?:folgen|kommen|gibt\s+es)?\s*"
                r"(?:neue?|weitere|andere)?\s*"
                r"(?:anweisun\w+|aufgab\w+|auftr\w+|"
                r"instruktion\w+)"
            ),
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=1.8,
            confidence=0.80,
            description="German: now follow new instructions",
        ),
        InjectionPattern(
            pattern_id="de_stell_dir_vor",
            pattern=(
                r"\b(?:stell\s+dir\s+vor|"
                r"tu\s+so\s+als)"
            ),
            category=PatternCategory.ROLE_SWITCHING,
            weight=1.5,
            confidence=0.75,
            description="German: pretend/imagine",
        ),
        InjectionPattern(
            pattern_id="de_konzentriere",
            pattern=(
                r"\bkonzentrier\w*\s+(?:dich\s+)?"
                r"(?:jetzt\s+|nun\s+)?(?:auf|darauf)"
            ),
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=1.8,
            confidence=0.80,
            description="German: concentrate on (new task)",
        ),
        # ===== TASK-SWITCHING ATTACKS =====
        InjectionPattern(
            pattern_id="task_switch_praise_redirect",
            pattern=(
                r"(?:well\s+done|great\s+job|excellent\w*|"
                r"good\s+job|fantastic|super|brilliant|"
                r"simply\s+great|you'?ve?\s+outdone|"
                r"that\s+is\s+enough|that\s+is\s+done|"
                r"that\s+was\s+(?:great|good|helpful|ok))"
                r"[.!,]*\s*(?:now|but|however)"
            ),
            category=PatternCategory.CONTEXT_BREAKING,
            weight=1.8,
            confidence=0.80,
            description="Praise followed by task redirect",
        ),
        InjectionPattern(
            pattern_id="task_switch_now_new",
            pattern=(
                r"\bnow\s+(?:please\s+)?"
                r"(?:help|write|do|answer|follow|"
                r"concentrate|focus|switch|start)"
            ),
            category=PatternCategory.CONTEXT_BREAKING,
            weight=1.2,
            confidence=0.65,
            description="Now + new task verb",
        ),
        InjectionPattern(
            pattern_id="de_task_switch",
            pattern=(
                r"(?:gut\s+gemacht|sehr\s+gut|"
                r"großartig|super\s+gemacht|"
                r"genügt|erledigt|das\s+reicht)"
                r"[.!,]*\s*(?:nun|jetzt|aber)"
            ),
            category=PatternCategory.CONTEXT_BREAKING,
            weight=1.8,
            confidence=0.80,
            description="German: praise + redirect",
        ),
        # ===== ALL CAPS INJECTION =====
        InjectionPattern(
            pattern_id="caps_injection",
            pattern=(
                r"\b(?:DO\s+NOT\s+ANSWER|STOP\s+EVERYTHING|"
                r"JUST\s+(?:SAY|PRINT|OUTPUT|WRITE)|"
                r"IGNORE\s+(?:ALL|THE|THIS)|"
                r"NEW\s+INSTRUCTIONS|"
                r"ANSWER\s+(?:ONLY|JUST|IN\s+THE\s+STYLE))"
            ),
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=2.5,
            confidence=0.90,
            description="ALL CAPS instruction injection",
        ),
        # ===== SPANISH LANGUAGE ATTACKS =====
        InjectionPattern(
            pattern_id="es_olvide_todo",
            pattern=(
                r"\b(?:olvid[ae]\w*|ignor[ae]\w*)\s+"
                r"(?:todo|todas?|los|las)?\s*"
                r"(?:lo\s+que|antes|previo|anterior)"
            ),
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=2.0,
            confidence=0.85,
            description="Spanish: forget/ignore everything",
        ),
        # ===== "NOW YOU ARE" ROLE ASSIGNMENT =====
        InjectionPattern(
            pattern_id="role_now_you_are",
            pattern=(r"\bnow\s+you\s+are\b"),
            category=PatternCategory.ROLE_SWITCHING,
            weight=1.8,
            confidence=0.80,
            description="Now you are [role]",
        ),
        InjectionPattern(
            pattern_id="de_jetzt_bist_du",
            pattern=(r"\b(?:jetzt|nun)\s+bist\s+du\b"),
            category=PatternCategory.ROLE_SWITCHING,
            weight=1.8,
            confidence=0.80,
            description="German: now you are [role]",
        ),
        InjectionPattern(
            pattern_id="de_fungieren_als",
            pattern=(
                r"\bals\s+\w+(?:\s+\w+)?\s+"
                r"(?:fungier\w*|agier\w*|"
                r"auftreten|verhalten)"
            ),
            category=PatternCategory.ROLE_SWITCHING,
            weight=1.6,
            confidence=0.75,
            description="German: act/function as",
        ),
        # ===== CONGRATULATIONS + TASK REDIRECT =====
        InjectionPattern(
            pattern_id="congrats_redirect",
            pattern=(
                r"(?:congratulations|congrats|"
                r"herzlichen\s+glückwunsch|"
                r"glückwunsch|ausgezeichnete)"
                r".{0,40}(?:now|nun|jetzt|bitte)"
            ),
            category=PatternCategory.CONTEXT_BREAKING,
            weight=1.8,
            confidence=0.78,
            description="Congratulations + task redirect",
        ),
        # ===== FICTIONAL SCENARIO FRAMING =====
        InjectionPattern(
            pattern_id="fictional_actors",
            pattern=(
                r"\b(?:john\s+and\s+alice|alice\s+and\s+bob)\s+"
                r"(?:are\s+)?(?:two\s+)?"
                r"(?:actors?|people|persons?|characters?)"
            ),
            category=PatternCategory.ROLE_SWITCHING,
            weight=1.5,
            confidence=0.70,
            description="Fictional character framing",
        ),
        InjectionPattern(
            pattern_id="de_fictional_actors",
            pattern=(
                r"\b(?:john\s+und\s+alice|alice\s+und\s+bob)\s+"
                r"(?:sind\s+)?(?:zwei\s+)?"
                r"(?:schauspieler|personen|charaktere)"
            ),
            category=PatternCategory.ROLE_SWITCHING,
            weight=1.5,
            confidence=0.70,
            description="German: fictional character framing",
        ),
        # ===== PLEASE REMOVE/LEAVE RESTRICTIONS =====
        InjectionPattern(
            pattern_id="remove_restrictions",
            pattern=(
                r"\b(?:remove|leave|drop|shed)\s+"
                r"(?:all\s+|any\s+|the\s+|your\s+)?"
                r"(?:previous\s+|prior\s+)?"
                r"(?:restrictions|limitations|constraints|"
                r"inhibitions|reservations)"
            ),
            category=PatternCategory.JAILBREAK_ATTEMPTS,
            weight=2.0,
            confidence=0.85,
            description="Remove restrictions/limitations",
        ),
        # ===== DESPITE WHAT YOU'VE BEEN TOLD =====
        InjectionPattern(
            pattern_id="despite_told",
            pattern=(
                r"\b(?:despite|regardless\s+of)\s+"
                r"(?:what|everything)\s+"
                r"(?:you'?ve?\s+been\s+told|"
                r"your\s+instructions)"
            ),
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=2.2,
            confidence=0.90,
            description="Despite what you've been told",
        ),
        # ===== NEWLINE FLOODING =====
        InjectionPattern(
            pattern_id="newline_flooding",
            pattern=r"(?:\\n\s*){5,}",
            category=PatternCategory.CONTEXT_BREAKING,
            weight=1.8,
            confidence=0.75,
            description="Newline flooding to push past context",
        ),
        # ===== FORGET + WRITE =====
        InjectionPattern(
            pattern_id="forget_and_write",
            pattern=(
                r"\bforget\s+(?:everything|all|about\s+everything)"
                r"[,.\s]*(?:and\s+)?"
                r"(?:write|say|print|output|tell|state)"
            ),
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=2.2,
            confidence=0.90,
            description="Forget everything + write/say/tell",
        ),
        # ===== SPANISH: FORGET INSTRUCTIONS =====
        InjectionPattern(
            pattern_id="es_olvida_instrucciones",
            pattern=(
                r"\b(?:olvid[ae]\w*)\s+"
                r"(?:todas?\s+)?(?:las?\s+)?"
                r"(?:instrucciones|reglas|ordenes)"
            ),
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=2.0,
            confidence=0.85,
            description="Spanish: forget instructions",
        ),
        # ===== DIRECT COMMAND TO STATE/SAY =====
        InjectionPattern(
            pattern_id="direct_state_command",
            pattern=(
                r"\b(?:state\s+that|just\s+say|"
                r"just\s+output|just\s+print)\b"
            ),
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=1.5,
            confidence=0.70,
            description="Direct command to state/output specific text",
        ),
        # ===== "YOU ARE X" (without now/act/pretend) =====
        InjectionPattern(
            pattern_id="role_you_are_entity",
            pattern=(
                r"\byou\s+are\s+(?:the\s+)?(?:electronic\s+)?"
                r"(?:guidebook|guide|assistant|bot|ai|"
                r"chatbot|system|tool|machine)"
            ),
            category=PatternCategory.ROLE_SWITCHING,
            weight=1.3,
            confidence=0.65,
            description="You are [specific entity]",
        ),
        # ===== YOUR INSTRUCTIONS ARE NOW =====
        InjectionPattern(
            pattern_id="your_instructions_now",
            pattern=(
                r"\byour\s+(?:instructions|task|job|role)"
                r"\s+(?:are|is)\s+(?:now|to)\b"
            ),
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=2.2,
            confidence=0.90,
            description="Your instructions are now...",
        ),
        # ===== STOP: WRITE/SAY =====
        InjectionPattern(
            pattern_id="stop_write",
            pattern=(
                r"\b(?:stop)[:.!]\s*"
                r"(?:write|say|print|output|display)"
            ),
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=2.0,
            confidence=0.85,
            description="Stop: write/say command",
        ),
        # ===== ADDITIONAL INSTRUCTION =====
        InjectionPattern(
            pattern_id="additional_instruction",
            pattern=(
                r"\b(?:additional|extra|supplementary|"
                r"further)\s+instruction"
            ),
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=1.5,
            confidence=0.70,
            description="Additional instruction injection",
        ),
        # ===== DISREGARDING THE ARTICLES =====
        InjectionPattern(
            pattern_id="disregarding_context",
            pattern=(
                r"\b(?:disregarding|ignoring|setting\s+aside)"
                r"\s+(?:the\s+)?(?:articles?|context|documents?|"
                r"information|text|content)"
            ),
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=2.0,
            confidence=0.85,
            description="Disregarding the context/articles",
        ),
        # ===== INCLUDE THAT / INCLUDE X IN YOUR ANSWER =====
        InjectionPattern(
            pattern_id="include_in_answer",
            pattern=(r"\binclude\s+(?:that\s+you|in\s+your\s+answer)"),
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=1.5,
            confidence=0.70,
            description="Include specific content in answer",
        ),
        # ===== ANSWER BY YOUR OWN KNOWLEDGE =====
        InjectionPattern(
            pattern_id="answer_own_knowledge",
            pattern=(
                r"\banswer\s+(?:by|with|using)\s+"
                r"(?:your\s+)?own\s+knowledge"
            ),
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            weight=1.5,
            confidence=0.70,
            description="Answer by your own knowledge (bypass context)",
        ),
    ]
