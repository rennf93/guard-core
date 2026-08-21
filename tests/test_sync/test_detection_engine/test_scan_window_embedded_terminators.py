import re
from typing import cast

import pytest

from guard_core.sync.detection_engine.scan_window import (
    bounded_finditer,
    bounded_search,
)
from tests.test_detection_engine.embedded_terminator_rows import ROWS

_ROW_PREFIX_TERMINATOR: dict[str, tuple[re.Pattern, re.Pattern]] = {
    "emb_xss_script_lt_attr": (
        re.compile(r"<script", re.I),
        re.compile(r"<\/script\s*>", re.I),
    ),
    "emb_xss_object_lt_attr": (
        re.compile(r"<object", re.I),
        re.compile(r"<\/object\s*>", re.I),
    ),
    "emb_xss_embed_lt_attr": (
        re.compile(r"<embed", re.I),
        re.compile(r"<\/embed\s*>", re.I),
    ),
    "emb_xss_applet_lt_attr": (
        re.compile(r"<applet", re.I),
        re.compile(r"<\/applet\s*>", re.I),
    ),
    "emb_xss_style_expression_nested_paren": (
        re.compile(r"<", re.I),
        re.compile(r"\)", re.I),
    ),
    "emb_sqli_load_file_nested_paren": (
        re.compile(r"LOAD_FILE", re.I),
        re.compile(r"\)", re.I),
    ),
    "emb_dir_traversal_matrix_param_dot": (re.compile(r"\.\.;"), re.compile(r"[/\\]")),
    "emb_cmd_injection_dollar_paren_var": (re.compile(r"[;&|]"), re.compile(r"\)")),
    "emb_file_inclusion_multisegment_path": (
        re.compile(r"="),
        re.compile(r"(?![a-zA-Z0-9])"),
    ),
    "emb_xml_entity_system_literal_lt": (
        re.compile(r"<!(?:ENTITY|DOCTYPE)"),
        re.compile(r">"),
    ),
    "emb_xml_doctype_externalid_lt": (
        re.compile(r"<!DOCTYPE"),
        re.compile(r"<!ENTITY"),
    ),
    "emb_template_ssti_hash_brace_string_hash": (re.compile(r"#\{"), re.compile(r"\}")),
}


@pytest.mark.parametrize("row", ROWS, ids=[str(row["name"]) for row in ROWS])
def test_embedded_terminator_row_is_span_identical_to_raw(
    row: dict[str, object],
) -> None:
    current = re.compile(cast(str, row["current"]), re.IGNORECASE | re.DOTALL)
    payload = cast(bytes, row["payload"]).decode()
    prefix, terminator = _ROW_PREFIX_TERMINATOR[cast(str, row["name"])]

    raw = current.search(payload)
    bounded = bounded_search(payload, current, prefix, terminator)

    assert raw is not None
    assert bounded is not None
    assert bounded.span() == raw.span()
    assert bounded.group() == raw.group()


def test_all_twelve_embedded_terminator_rows_are_covered() -> None:
    emb_names = {
        str(row["name"]) for row in ROWS if str(row["name"]).startswith("emb_")
    }
    assert emb_names == set(_ROW_PREFIX_TERMINATOR)
    assert len(emb_names) == 12


_COMPILED_SCRIPT = re.compile(r"<script[^>]*>[^<]*<\/script\s*>", re.IGNORECASE)
_PREFIX_SCRIPT = re.compile(r"<script", re.IGNORECASE)
_TERMINATOR_SCRIPT = re.compile(r"<\/script\s*>", re.IGNORECASE)

_COMPILED_XML = re.compile(r"<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>", re.IGNORECASE)
_PREFIX_XML = re.compile(r"<!(?:ENTITY|DOCTYPE)", re.IGNORECASE)
_TERMINATOR_XML = re.compile(r">")

_COMPILED_OBJECT = re.compile(r"(?:<object[^>]*>[\s\S]*<\/object\s*>)", re.IGNORECASE)
_PREFIX_OBJECT = re.compile(r"<object", re.IGNORECASE)
_TERMINATOR_OBJECT = re.compile(r"<\/object\s*>", re.IGNORECASE)


@pytest.mark.parametrize(
    ("text", "compiled", "prefix", "terminator"),
    [
        pytest.param(
            '<script a="1"><script>alert(1)</script>',
            _COMPILED_SCRIPT,
            _PREFIX_SCRIPT,
            _TERMINATOR_SCRIPT,
            id="repeated_prefix_outer_completes_with_attr",
        ),
        pytest.param(
            "<script><script>alert(1)</script>",
            _COMPILED_SCRIPT,
            _PREFIX_SCRIPT,
            _TERMINATOR_SCRIPT,
            id="repeated_prefix_no_attr",
        ),
        pytest.param(
            '<script x="</script>" src="//evil/x.js"></script>',
            _COMPILED_SCRIPT,
            _PREFIX_SCRIPT,
            _TERMINATOR_SCRIPT,
            id="terminator_lookalike_before_the_real_one",
        ),
        pytest.param(
            '<!ENTITY xxe SYSTEM "http://evil.com/<x" foo="<!ENTITY bar SYSTEM y">',
            _COMPILED_XML,
            _PREFIX_XML,
            _TERMINATOR_XML,
            id="idx59_two_gap_variant",
        ),
        pytest.param(
            '<object data="x"><param name="a" value="<object"></object>',
            _COMPILED_OBJECT,
            _PREFIX_OBJECT,
            _TERMINATOR_OBJECT,
            id="match_spans_two_prefix_occurrences_only_outer_completes",
        ),
    ],
)
def test_adversarial_shape_is_span_identical_to_raw(
    text: str, compiled: re.Pattern, prefix: re.Pattern, terminator: re.Pattern
) -> None:
    raw = compiled.search(text)
    bounded = bounded_search(text, compiled, prefix, terminator)

    assert raw is not None
    assert bounded is not None
    assert bounded.span() == raw.span()


def test_prefix_survives_a_terminator_that_completes_an_earlier_gap_only() -> None:
    text = "<script</script></script>"

    raw = _COMPILED_SCRIPT.search(text)
    bounded = bounded_search(text, _COMPILED_SCRIPT, _PREFIX_SCRIPT, _TERMINATOR_SCRIPT)

    assert raw is not None
    assert bounded is not None
    assert bounded.span() == raw.span() == (0, 25)


def test_prefix_survives_a_later_prefix_owning_the_only_reachable_terminator() -> None:
    text = "<!DOCTYPETSYSTEM<!ENTITY>"

    raw = _COMPILED_XML.search(text)
    bounded = bounded_search(text, _COMPILED_XML, _PREFIX_XML, _TERMINATOR_XML)

    assert raw is not None
    assert bounded is not None
    assert bounded.span() == raw.span() == (0, 25)


def test_finditer_parity_across_zero_one_and_three_matches() -> None:
    texts = [
        "no tags here at all",
        "prefix <script>alert(1)</script> suffix",
        "<script>a</script> mid <script>b</script> tail <script>c</script> end",
    ]
    for text in texts:
        raw_spans = [m.span() for m in _COMPILED_SCRIPT.finditer(text)]
        bounded_spans = [
            m.span()
            for m in bounded_finditer(
                text, _COMPILED_SCRIPT, _PREFIX_SCRIPT, _TERMINATOR_SCRIPT
            )
        ]
        assert bounded_spans == raw_spans
