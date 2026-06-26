import base64
import urllib.parse
from collections.abc import Callable, Iterator
from dataclasses import dataclass

_HOMOGLYPHS = {"<": "＜", ">": "＞", "/": "∕", ";": ";", "|": "ǀ"}
_HTML_NAMED = {"<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&#39;"}


def _url_encode(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def _double_url_encode(value: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(value, safe=""), safe="")


def _html_entity_named(value: str) -> str:
    return "".join(_HTML_NAMED.get(char, char) for char in value)


def _html_entity_decimal(value: str) -> str:
    return "".join(f"&#{ord(char)};" for char in value)


def _html_entity_hex(value: str) -> str:
    return "".join(f"&#x{ord(char):x};" for char in value)


def _unicode_homograph(value: str) -> str:
    return "".join(_HOMOGLYPHS.get(char, char) for char in value)


def _mixed_case(value: str) -> str:
    return "".join(
        char.upper() if index % 2 else char.lower() for index, char in enumerate(value)
    )


def _whitespace_variation(value: str) -> str:
    return value.replace(" ", "\t")


def _base64_wrap(value: str) -> str:
    return base64.b64encode(value.encode()).decode()


def _unicode_escape(value: str) -> str:
    return "".join(f"\\u{ord(char):04x}" for char in value)


def _hex_escape(value: str) -> str:
    return "".join(f"\\x{ord(char):02x}" if ord(char) < 256 else char for char in value)


def _null_byte(value: str) -> str:
    return value + "\x00"


TRANSFORMS: dict[str, Callable[[str], str]] = {
    "url_encode": _url_encode,
    "double_url_encode": _double_url_encode,
    "html_entity_named": _html_entity_named,
    "html_entity_decimal": _html_entity_decimal,
    "html_entity_hex": _html_entity_hex,
    "unicode_homograph": _unicode_homograph,
    "mixed_case": _mixed_case,
    "whitespace_variation": _whitespace_variation,
    "base64_wrap": _base64_wrap,
    "unicode_escape": _unicode_escape,
    "hex_escape": _hex_escape,
    "null_byte": _null_byte,
}

CURATED_CHAINS: tuple[tuple[str, ...], ...] = (
    ("url_encode", "double_url_encode"),
    ("html_entity_decimal", "url_encode"),
    ("mixed_case", "url_encode"),
    ("unicode_homograph", "url_encode"),
    ("whitespace_variation", "mixed_case"),
    ("html_entity_named", "mixed_case"),
)


@dataclass(frozen=True)
class Variant:
    payload: str
    seed_id: str
    attack_class: str
    technique_chain: tuple[str, ...]


def _apply_chain(payload: str, chain: tuple[str, ...]) -> str:
    result = payload
    for name in chain:
        result = TRANSFORMS[name](result)
    return result


def generate_variants(
    seed_id: str, attack_class: str, payload: str
) -> Iterator[Variant]:
    yield Variant(payload, seed_id, attack_class, ())
    for name in TRANSFORMS:
        yield Variant(TRANSFORMS[name](payload), seed_id, attack_class, (name,))
    for chain in CURATED_CHAINS:
        yield Variant(_apply_chain(payload, chain), seed_id, attack_class, chain)
