import json
from typing import Any
from urllib.parse import quote

from tests.redaction_gate.axes import (
    ASSIGN_MAP,
    SEPARATOR_MAP,
    TRIGGER_TEXT,
    WHITESPACE_MAP,
)


def apply_casing(name: str, casing: str) -> str:
    if casing == "lower":
        return name.lower()
    if casing == "upper":
        return name.upper()
    return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(name))


def apply_quoting(value: str, quoting: str) -> str:
    if quoting == "double":
        return f'"{value}"'
    if quoting == "single":
        return f"'{value}'"
    return value


def apply_wrapper(fragment: str, wrapper: str) -> str:
    if wrapper == "nested_data":
        return f"data={fragment}"
    if wrapper == "filename":
        return f'filename="{fragment}"'
    if wrapper == "json_leaf":
        return json.dumps({"note": fragment})
    if wrapper == "xml":
        return f"<note>{fragment}</note>"
    return fragment


def _encode_char_rounds(ch: str, rounds: int) -> str:
    enc = ch
    for _ in range(rounds):
        enc = quote(enc, safe="")
    return enc


def apply_pct_encoding(blob: str, rounds: int, target: str, separator_char: str) -> str:
    if rounds == 0:
        return blob
    if target == "whole":
        value = blob
        for _ in range(rounds):
            value = quote(value, safe="")
        return value
    ch = "=" if target == "equals" else separator_char
    if not ch:
        return blob
    return blob.replace(ch, _encode_char_rounds(ch, rounds))


def _target_tokens(
    name: str,
    assign: str,
    ws_before: str,
    ws_after: str,
    raw_value: str,
    quoted_value: str,
    value_mode: str,
) -> list[str]:
    prefix = f"{name}{ws_before}{assign}{ws_after}"
    if value_mode == "empty_split":
        return [prefix, raw_value]
    return [f"{prefix}{quoted_value}"]


def _ordered_parts(target_tokens: list[str], position: str) -> list[str]:
    decoys = ["x=1", "y=2"]
    if position == "first":
        return target_tokens + decoys
    if position == "second":
        return [decoys[0]] + target_tokens + [decoys[1]]
    return decoys + target_tokens


def build_blob(axes: dict[str, Any], secret_value: str) -> str:
    name = axes["name"]
    if axes["name_suffix"] == "plus":
        name = name + "+"
    name = apply_casing(name, axes["casing"])
    assign = ASSIGN_MAP[axes["assign"]]
    ws_before, ws_after = WHITESPACE_MAP[axes["whitespace"]]
    trigger_text = TRIGGER_TEXT.get(axes["trigger"], "")
    raw_value = f"{secret_value} {trigger_text}" if trigger_text else secret_value

    if axes["wrapper"] == "xml_attr":
        fragment = f'<user {name}="{raw_value}"/>'
    else:
        quoted_value = apply_quoting(raw_value, axes["quoting"])
        target_tokens = _target_tokens(
            name,
            assign,
            ws_before,
            ws_after,
            raw_value,
            quoted_value,
            axes["value_mode"],
        )
        parts = _ordered_parts(target_tokens, axes["position"])
        sep = SEPARATOR_MAP[axes["separator"]]
        fragment = apply_wrapper(sep.join(parts), axes["wrapper"])

    rounds, target = axes["pct"]
    return apply_pct_encoding(
        fragment, rounds, target, SEPARATOR_MAP[axes["separator"]]
    )
