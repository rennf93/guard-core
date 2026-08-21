import re
from collections.abc import Generator

import pytest

from guard_core.handlers.suspatterns_handler import (
    _GLOB_WILDCARD_ATOM_RE,
    _QUOTE_SPLICE_CANDIDATE_RE,
    SusPatternsManager,
    _glob_wildcard_token_is_dangerous_command,
    _quote_splice_token_is_dangerous_command,
)


@pytest.fixture
def manager() -> Generator[SusPatternsManager, None, None]:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config

    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    new_instance = SusPatternsManager()

    yield new_instance

    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config


async def test_brace_expansion_at_content_start_is_detected(
    manager: SusPatternsManager,
) -> None:
    result = await manager.detect(
        "{cat,config.ini}",
        "127.0.0.1",
        context="query_param",
    )
    assert result["is_threat"] is True
    regex_threats = [t for t in result["threats"] if t["type"] == "regex"]
    assert any(t["category"] == "cmd_injection" for t in regex_threats)


async def test_brace_expansion_with_non_command_first_item_is_detected(
    manager: SusPatternsManager,
) -> None:
    result = await manager.detect(
        "{banana,config.ini}",
        "127.0.0.1",
        context="query_param",
    )
    assert result["is_threat"] is True
    regex_threats = [t for t in result["threats"] if t["type"] == "regex"]
    assert any(t["category"] == "cmd_injection" for t in regex_threats)


async def test_brace_expansion_after_operator_boundary_is_detected(
    manager: SusPatternsManager,
) -> None:
    result = await manager.detect(
        "id=5;{rm,-rf,/}",
        "127.0.0.1",
        context="request_body",
    )
    assert result["is_threat"] is True
    regex_threats = [t for t in result["threats"] if t["type"] == "regex"]
    assert any(t["category"] == "cmd_injection" for t in regex_threats)


async def test_brace_expansion_embedded_in_prose_is_not_flagged(
    manager: SusPatternsManager,
) -> None:
    result = await manager.detect(
        "notes: {cat,dog,bird} are pets",
        "127.0.0.1",
        context="request_body",
    )
    assert result["is_threat"] is False


async def test_json_object_shape_is_not_flagged_as_brace_expansion(
    manager: SusPatternsManager,
) -> None:
    result = await manager.detect(
        '{"action":"fork","repo":"octocat/hello-world"}',
        "127.0.0.1",
        context="request_body",
    )
    regex_threats = [t for t in result["threats"] if t["type"] == "regex"]
    assert not any(t["category"] == "cmd_injection" for t in regex_threats)


async def test_quote_splice_uniform_single_char_run_is_detected(
    manager: SusPatternsManager,
) -> None:
    result = await manager.detect(
        "c'a't config.ini",
        "127.0.0.1",
        context="query_param",
    )
    assert result["is_threat"] is True
    matched_patterns = [t["pattern"] for t in result["threats"] if t["type"] == "regex"]
    assert _QUOTE_SPLICE_CANDIDATE_RE in matched_patterns


async def test_quote_splice_non_command_uniform_run_is_detected(
    manager: SusPatternsManager,
) -> None:
    result = await manager.detect(
        "b'a'n'a'n'a config.ini",
        "127.0.0.1",
        context="query_param",
    )
    assert result["is_threat"] is True
    matched_patterns = [t["pattern"] for t in result["threats"] if t["type"] == "regex"]
    assert _QUOTE_SPLICE_CANDIDATE_RE in matched_patterns


async def test_glob_wildcard_after_operator_boundary_is_detected(
    manager: SusPatternsManager,
) -> None:
    result = await manager.detect(
        "|c?t config.ini",
        "127.0.0.1",
        context="query_param",
    )
    assert result["is_threat"] is True
    matched_patterns = [t["pattern"] for t in result["threats"] if t["type"] == "regex"]
    assert _GLOB_WILDCARD_ATOM_RE in matched_patterns


async def test_python_getattr_indirection_is_detected(
    manager: SusPatternsManager,
) -> None:
    result = await manager.detect(
        "getattr(__import__('os'),'popen')('id')",
        "127.0.0.1",
        context="query_param",
    )
    assert result["is_threat"] is True
    regex_threats = [t for t in result["threats"] if t["type"] == "regex"]
    assert any(t["category"] == "code_injection" for t in regex_threats)


async def test_quote_splice_non_dangerous_token_is_not_flagged(
    manager: SusPatternsManager,
) -> None:
    result = await manager.detect(
        "foo'ba'r",
        "127.0.0.1",
        context="query_param",
    )
    assert result["is_threat"] is False


async def test_glob_wildcard_without_operator_boundary_is_not_flagged(
    manager: SusPatternsManager,
) -> None:
    result = await manager.detect(
        "fo?bar",
        "127.0.0.1",
        context="query_param",
    )
    assert result["is_threat"] is False


async def test_glob_wildcard_bare_dangerous_shape_without_boundary_is_not_flagged(
    manager: SusPatternsManager,
) -> None:
    result = await manager.detect(
        "c?t config.ini",
        "127.0.0.1",
        context="query_param",
    )
    assert result["is_threat"] is False


def test_quote_splice_validator_true_for_uniform_single_char_run() -> None:
    match = re.search(_QUOTE_SPLICE_CANDIDATE_RE, "c'a't")
    assert match is not None
    assert _quote_splice_token_is_dangerous_command(match) is True


def test_quote_splice_validator_true_for_run_after_non_uniform_prefix() -> None:
    match = re.search(_QUOTE_SPLICE_CANDIDATE_RE, "prefix'c'a't")
    assert match is not None
    assert _quote_splice_token_is_dangerous_command(match) is True


def test_quote_splice_validator_false_for_mixed_length_fragments() -> None:
    match = re.search(_QUOTE_SPLICE_CANDIDATE_RE, "foo'ba'r")
    assert match is not None
    assert _quote_splice_token_is_dangerous_command(match) is False


def test_quote_splice_validator_false_for_two_single_char_fragments() -> None:
    match = re.search(_QUOTE_SPLICE_CANDIDATE_RE, "I'm")
    assert match is not None
    assert _quote_splice_token_is_dangerous_command(match) is False


def test_glob_wildcard_validator_true_after_operator_boundary() -> None:
    match = re.search(_GLOB_WILDCARD_ATOM_RE, "|c?t")
    assert match is not None
    assert _glob_wildcard_token_is_dangerous_command(match) is True


def test_glob_wildcard_validator_true_after_dollar_paren_boundary() -> None:
    match = re.search(_GLOB_WILDCARD_ATOM_RE, "$(c?t")
    assert match is not None
    assert _glob_wildcard_token_is_dangerous_command(match) is True


def test_glob_wildcard_validator_false_without_operator_boundary() -> None:
    match = re.search(_GLOB_WILDCARD_ATOM_RE, "c?t")
    assert match is not None
    assert _glob_wildcard_token_is_dangerous_command(match) is False


def test_glob_wildcard_validator_false_for_benign_token() -> None:
    match = re.search(_GLOB_WILDCARD_ATOM_RE, "fo?bar")
    assert match is not None
    assert _glob_wildcard_token_is_dangerous_command(match) is False


def test_glob_wildcard_validator_false_for_all_wildcard_token() -> None:
    match = re.search(_GLOB_WILDCARD_ATOM_RE, "?*")
    assert match is not None
    assert _glob_wildcard_token_is_dangerous_command(match) is False


def test_glob_wildcard_validator_false_for_short_literal_with_star() -> None:
    match = re.search(_GLOB_WILDCARD_ATOM_RE, "c*")
    assert match is not None
    assert _glob_wildcard_token_is_dangerous_command(match) is False
