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
