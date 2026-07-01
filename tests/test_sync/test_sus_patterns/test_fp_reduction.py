def _flagged(manager, payload: str) -> bool:
    result = manager.detect(payload, "127.0.0.1", context="unknown")
    return result["is_threat"]


def test_select_star_still_flagged(sus_patterns_manager_with_detection):
    assert _flagged(sus_patterns_manager_with_detection, "SELECT * FROM users")


def test_select_where_still_flagged(sus_patterns_manager_with_detection):
    assert _flagged(
        sus_patterns_manager_with_detection, "SELECT password FROM users WHERE id=1"
    )


def test_select_prose_not_flagged(sus_patterns_manager_with_detection):
    assert not _flagged(
        sus_patterns_manager_with_detection,
        "I'll select a few items from the catalog for you",
    )


def test_select_candidates_prose_not_flagged(sus_patterns_manager_with_detection):
    assert not _flagged(
        sus_patterns_manager_with_detection,
        "we will select candidates from the applicant pool",
    )


def test_order_by_attack_flagged(sus_patterns_manager_with_detection):
    assert _flagged(sus_patterns_manager_with_detection, "1' ORDER BY 1--")


def test_order_by_prose_not_flagged(sus_patterns_manager_with_detection):
    assert not _flagged(
        sus_patterns_manager_with_detection,
        "sort the results, order by 1 ascending then by name",
    )


def test_ddl_attack_flagged(sus_patterns_manager_with_detection):
    assert _flagged(sus_patterns_manager_with_detection, "'; DROP TABLE users;--")


def test_ddl_prose_not_flagged(sus_patterns_manager_with_detection):
    assert not _flagged(
        sus_patterns_manager_with_detection,
        "drop table 7 is reserved for the wedding party",
    )


def test_erb_attack_flagged(sus_patterns_manager_with_detection):
    assert _flagged(sus_patterns_manager_with_detection, "<%= 7*7 %>")


def test_erb_docs_not_flagged(sus_patterns_manager_with_detection):
    assert not _flagged(
        sus_patterns_manager_with_detection,
        "render <%= @user.name %> inside your erb view",
    )


def test_nosql_where_op_flagged(sus_patterns_manager_with_detection):
    assert _flagged(
        sus_patterns_manager_with_detection, '{"$where": "this.password.length > 0"}'
    )


def test_nosql_ne_null_flagged(sus_patterns_manager_with_detection):
    assert _flagged(sus_patterns_manager_with_detection, '{"$ne":null}')


def test_nosql_legit_value_not_flagged(sus_patterns_manager_with_detection):
    assert not _flagged(
        sus_patterns_manager_with_detection,
        'the mongo filter {"$gt": 5} returns larger values',
    )
