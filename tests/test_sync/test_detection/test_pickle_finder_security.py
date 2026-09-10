import itertools
import random

import pytest

from guard_core.sync.handlers._suspatterns_matchers import (
    _DESERIALIZATION_PICKLE_GLOBAL_GENERIC_COMPILED_RE,
    _pickle_global_generic_finditer,
)


@pytest.mark.parametrize(
    "module", ["cfoo.1cbar", "cfoo..cbar", "cfoo.cbar", "cK", "cİ", "cſ"]
)
@pytest.mark.parametrize("name", ["run", "K", "İ", "ſ"])
def test_pickle_finder_preserves_candidates_after_bad_segments(
    module: str, name: str
) -> None:
    text = f"{module}\n{name}\nR"
    compiled = _DESERIALIZATION_PICKLE_GLOBAL_GENERIC_COMPILED_RE
    expected = [(m.span(), m.groups()) for m in compiled.finditer(text)]
    assert expected
    assert [
        (m.span(), m.groups()) for m in _pickle_global_generic_finditer(text, compiled)
    ] == expected


def test_pickle_finder_differential_module_grammar() -> None:
    rng = random.Random(9303)
    compiled = _DESERIALIZATION_PICKLE_GLOBAL_GENERIC_COMPILED_RE
    atoms = ["c", "C", "x", "1", ".", "..", "_", "K", "İ", "ſ", " "]
    cases = ["".join(row) + "\nrun\nR" for row in itertools.product(atoms, repeat=3)]
    cases.extend(
        "".join(rng.choices(atoms, k=rng.randrange(1, 40))) + "\nrun\nR"
        for _ in range(2000)
    )
    for text in cases:
        expected = [(m.span(), m.groups()) for m in compiled.finditer(text)]
        actual = [
            (m.span(), m.groups())
            for m in _pickle_global_generic_finditer(text, compiled)
        ]
        assert actual == expected, (text, actual, expected)
