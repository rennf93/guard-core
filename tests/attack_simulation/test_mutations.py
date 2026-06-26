from tests.attack_simulation.mutations import (
    TRANSFORMS,
    Variant,
    generate_variants,
)


def test_individual_transforms():
    assert TRANSFORMS["url_encode"]("<a>") == "%3Ca%3E"
    assert TRANSFORMS["double_url_encode"]("<") == "%253C"
    assert TRANSFORMS["html_entity_decimal"]("<") == "&#60;"
    assert TRANSFORMS["html_entity_hex"]("<") == "&#x3c;"
    assert TRANSFORMS["mixed_case"]("abcd") == "aBcD"
    assert TRANSFORMS["base64_wrap"]("ab") == "YWI="


def test_generate_variants_shape_and_metadata():
    variants = list(generate_variants("xss-0", "xss", "<script>"))
    chains = [v.technique_chain for v in variants]
    assert () in chains
    assert ("url_encode",) in chains
    assert all(isinstance(v, Variant) for v in variants)
    assert all(v.seed_id == "xss-0" and v.attack_class == "xss" for v in variants)
    unmutated = next(v for v in variants if v.technique_chain == ())
    assert unmutated.payload == "<script>"
    assert len(variants) == 1 + len(TRANSFORMS) + 6


def test_generate_variants_is_deterministic():
    a = [v.payload for v in generate_variants("s", "xss", "<x>")]
    b = [v.payload for v in generate_variants("s", "xss", "<x>")]
    assert a == b
