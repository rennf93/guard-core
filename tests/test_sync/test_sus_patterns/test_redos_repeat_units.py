import pytest

from guard_core.sync.detection_engine._redos_repeat_units import _repeat_group_units


@pytest.mark.parametrize("quantifier", ["*", "+", "{0,100000}", "{100}"])
def test_multichar_repeat_unit_preserves_both_character_domains(
    quantifier: str,
) -> None:
    pattern = rf"(?:[a-m][n-z]){quantifier}(?:[a-m][n-z]){quantifier}X"
    pairs = _repeat_group_units(pattern, 0)
    assert ("", "an") in pairs
    assert all(unit == "an" for _prefix, unit in pairs)


def test_group_units_remain_paired_with_their_own_branch_prefix() -> None:
    pairs = _repeat_group_units(r"\A(?:foo(?:[a-m][n-z])+|bar(?:[0-4][5-9])+)!", 0)
    assert pairs == [("foo", "an"), ("bar", "05")]


@pytest.mark.parametrize("pattern", ["[", "abc", r"a+a+$"])
def test_pattern_without_multichar_repeat_has_no_group_unit(pattern: str) -> None:
    assert _repeat_group_units(pattern, 0) == []


def test_unreachable_repeated_region_does_not_return_an_empty_probe_set() -> None:
    with pytest.raises(TimeoutError, match="repeat-site prefixes"):
        _repeat_group_units(r"\A(?=f.o)foo(?:[a-m][n-z])+X", 0)


def test_many_distinct_repeat_units_fail_closed_at_the_candidate_budget() -> None:
    alternatives = "|".join(f"X{index:04}" for index in range(4097))
    with pytest.raises(TimeoutError, match="repeat-unit budget"):
        _repeat_group_units(f"(?:{alternatives}){{2}}", 0)


def test_repeat_unit_text_budget_counts_across_distinct_sites(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "guard_core.sync.detection_engine._redos_repeat_units._REPEAT_UNIT_TEXT_BUDGET",
        8,
    )
    with pytest.raises(TimeoutError, match="repeat-unit text budget"):
        _repeat_group_units(r"X(?:ab){2}Y(?:cd){2}", 0)
