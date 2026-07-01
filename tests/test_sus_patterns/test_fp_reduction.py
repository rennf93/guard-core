import pytest


async def _flagged(manager, payload: str) -> bool:
    result = await manager.detect(payload, "127.0.0.1", context="unknown")
    return result["is_threat"]


@pytest.mark.asyncio
async def test_select_star_still_flagged(sus_patterns_manager_with_detection):
    assert await _flagged(sus_patterns_manager_with_detection, "SELECT * FROM users")


@pytest.mark.asyncio
async def test_select_where_still_flagged(sus_patterns_manager_with_detection):
    assert await _flagged(
        sus_patterns_manager_with_detection, "SELECT password FROM users WHERE id=1"
    )


@pytest.mark.asyncio
async def test_select_prose_not_flagged(sus_patterns_manager_with_detection):
    assert not await _flagged(
        sus_patterns_manager_with_detection,
        "I'll select a few items from the catalog for you",
    )


@pytest.mark.asyncio
async def test_select_candidates_prose_not_flagged(sus_patterns_manager_with_detection):
    assert not await _flagged(
        sus_patterns_manager_with_detection,
        "we will select candidates from the applicant pool",
    )


@pytest.mark.asyncio
async def test_order_by_attack_flagged(sus_patterns_manager_with_detection):
    assert await _flagged(sus_patterns_manager_with_detection, "1' ORDER BY 1--")


@pytest.mark.asyncio
async def test_order_by_prose_not_flagged(sus_patterns_manager_with_detection):
    assert not await _flagged(
        sus_patterns_manager_with_detection,
        "sort the results, order by 1 ascending then by name",
    )


@pytest.mark.asyncio
async def test_ddl_attack_flagged(sus_patterns_manager_with_detection):
    assert await _flagged(sus_patterns_manager_with_detection, "'; DROP TABLE users;--")


@pytest.mark.asyncio
async def test_ddl_prose_not_flagged(sus_patterns_manager_with_detection):
    assert not await _flagged(
        sus_patterns_manager_with_detection,
        "drop table 7 is reserved for the wedding party",
    )


@pytest.mark.asyncio
async def test_erb_attack_flagged(sus_patterns_manager_with_detection):
    assert await _flagged(sus_patterns_manager_with_detection, "<%= 7*7 %>")


@pytest.mark.asyncio
async def test_erb_docs_not_flagged(sus_patterns_manager_with_detection):
    assert not await _flagged(
        sus_patterns_manager_with_detection,
        "render <%= @user.name %> inside your erb view",
    )


@pytest.mark.asyncio
async def test_nosql_where_op_flagged(sus_patterns_manager_with_detection):
    assert await _flagged(
        sus_patterns_manager_with_detection, '{"$where": "this.password.length > 0"}'
    )


@pytest.mark.asyncio
async def test_nosql_ne_null_flagged(sus_patterns_manager_with_detection):
    assert await _flagged(sus_patterns_manager_with_detection, '{"$ne":null}')


@pytest.mark.asyncio
async def test_nosql_legit_value_not_flagged(sus_patterns_manager_with_detection):
    assert not await _flagged(
        sus_patterns_manager_with_detection,
        'the mongo filter {"$gt": 5} returns larger values',
    )
