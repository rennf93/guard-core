import re
from collections.abc import Generator

import pytest

from guard_core.sync.handlers.suspatterns_handler import (
    _CTX_CMD_INJECTION,
    _CTX_CMS_PROBING,
    _CTX_DIR_TRAVERSAL,
    _CTX_FILE_INCLUSION,
    _CTX_FILE_UPLOAD,
    _CTX_HTTP_SPLIT,
    _CTX_LDAP,
    _CTX_NOSQL,
    _CTX_PATH_TRAVERSAL,
    _CTX_RECON,
    _CTX_SENSITIVE_FILE,
    _CTX_SQLI,
    _CTX_SSRF,
    _CTX_TEMPLATE,
    _CTX_XML,
    _CTX_XSS,
    ALL_DETECTION_CATEGORIES,
    CATEGORY_CONTEXT_MAP,
    SusPatternsManager,
)

EXPECTED_CATEGORIES = frozenset(
    {
        "xss",
        "sqli",
        "dir_traversal",
        "path_traversal",
        "cmd_injection",
        "file_inclusion",
        "ldap",
        "xml",
        "ssrf",
        "nosql",
        "file_upload",
        "template",
        "http_split",
        "sensitive_file",
        "cms_probing",
        "recon",
    }
)


def test_all_detection_categories_is_frozenset() -> None:
    assert isinstance(ALL_DETECTION_CATEGORIES, frozenset)


def test_all_detection_categories_matches_expected() -> None:
    assert ALL_DETECTION_CATEGORIES == EXPECTED_CATEGORIES


def test_category_context_map_covers_every_category() -> None:
    assert set(CATEGORY_CONTEXT_MAP.keys()) == set(ALL_DETECTION_CATEGORIES)


def test_category_context_map_values_are_frozensets_of_strings() -> None:
    for category, contexts in CATEGORY_CONTEXT_MAP.items():
        assert isinstance(contexts, frozenset), category
        assert all(isinstance(c, str) for c in contexts), category


def test_category_context_map_identity_with_existing_constants() -> None:
    assert CATEGORY_CONTEXT_MAP["xss"] is _CTX_XSS
    assert CATEGORY_CONTEXT_MAP["sqli"] is _CTX_SQLI
    assert CATEGORY_CONTEXT_MAP["dir_traversal"] is _CTX_DIR_TRAVERSAL
    assert CATEGORY_CONTEXT_MAP["path_traversal"] is _CTX_PATH_TRAVERSAL
    assert CATEGORY_CONTEXT_MAP["cmd_injection"] is _CTX_CMD_INJECTION
    assert CATEGORY_CONTEXT_MAP["file_inclusion"] is _CTX_FILE_INCLUSION
    assert CATEGORY_CONTEXT_MAP["ldap"] is _CTX_LDAP
    assert CATEGORY_CONTEXT_MAP["xml"] is _CTX_XML
    assert CATEGORY_CONTEXT_MAP["ssrf"] is _CTX_SSRF
    assert CATEGORY_CONTEXT_MAP["nosql"] is _CTX_NOSQL
    assert CATEGORY_CONTEXT_MAP["file_upload"] is _CTX_FILE_UPLOAD
    assert CATEGORY_CONTEXT_MAP["template"] is _CTX_TEMPLATE
    assert CATEGORY_CONTEXT_MAP["http_split"] is _CTX_HTTP_SPLIT
    assert CATEGORY_CONTEXT_MAP["sensitive_file"] is _CTX_SENSITIVE_FILE
    assert CATEGORY_CONTEXT_MAP["cms_probing"] is _CTX_CMS_PROBING
    assert CATEGORY_CONTEXT_MAP["recon"] is _CTX_RECON


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


def test_compiled_pattern_tuples_have_three_elements(
    manager: SusPatternsManager,
) -> None:
    assert manager.compiled_patterns
    for entry in manager.compiled_patterns:
        assert len(entry) == 3, entry
        pattern, contexts, category = entry
        assert isinstance(pattern, re.Pattern)
        assert isinstance(contexts, frozenset)
        assert isinstance(category, str)
        assert category in ALL_DETECTION_CATEGORIES


def test_pattern_definitions_type_annotation_is_3tuple() -> None:
    assert (
        SusPatternsManager.__annotations__["compiled_patterns"]
        == list[tuple[re.Pattern, frozenset[str], str]]
    )


def test_regex_threat_dict_includes_category(
    manager: SusPatternsManager,
) -> None:
    result = manager.detect(
        "<script>alert('xss')</script>",
        "127.0.0.1",
        context="query_param",
    )
    assert result["is_threat"] is True
    regex_threats = [t for t in result["threats"] if t["type"] == "regex"]
    assert regex_threats, result
    assert all("category" in t for t in regex_threats)
    assert all(t["category"] in ALL_DETECTION_CATEGORIES for t in regex_threats)
    assert any(t["category"] == "xss" for t in regex_threats)


def test_detect_with_enabled_categories_skips_disabled(
    manager: SusPatternsManager,
) -> None:
    result = manager.detect(
        "<script>alert('xss')</script>",
        "127.0.0.1",
        context="query_param",
        enabled_categories={"sqli"},
    )
    assert result["is_threat"] is False, result


def test_detect_with_enabled_categories_runs_enabled(
    manager: SusPatternsManager,
) -> None:
    result = manager.detect(
        "<script>alert('xss')</script>",
        "127.0.0.1",
        context="query_param",
        enabled_categories={"xss"},
    )
    assert result["is_threat"] is True


def test_detect_without_enabled_categories_runs_all(
    manager: SusPatternsManager,
) -> None:
    result = manager.detect(
        "<script>alert('xss')</script>",
        "127.0.0.1",
        context="query_param",
    )
    assert result["is_threat"] is True


def test_detect_enabled_categories_preserves_unknown_context_fallback(
    manager: SusPatternsManager,
) -> None:
    result = manager.detect(
        "<script>alert('xss')</script>",
        "127.0.0.1",
        context="not_a_real_context",
        enabled_categories={"xss"},
    )
    assert result["is_threat"] is True


def test_detect_enabled_categories_empty_set_disables_everything(
    manager: SusPatternsManager,
) -> None:
    result = manager.detect(
        "<script>alert('xss')</script>",
        "127.0.0.1",
        context="query_param",
        enabled_categories=set(),
    )
    assert result["is_threat"] is False


def test_detect_custom_patterns_run_regardless_of_enabled_categories(
    manager: SusPatternsManager,
) -> None:
    manager.add_pattern(r"custom_marker_ABC", custom=True)
    try:
        result = manager.detect(
            "custom_marker_ABC",
            "127.0.0.1",
            context="query_param",
            enabled_categories={"sqli"},
        )
        assert result["is_threat"] is True
    finally:
        manager.remove_pattern(r"custom_marker_ABC", custom=True)
