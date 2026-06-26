import pytest


async def _detected(manager, payload: str) -> bool:
    result = await manager.detect(payload, "127.0.0.1", context="unknown")
    return result["is_threat"]


@pytest.mark.asyncio
async def test_comment_between_keywords_detected(sus_patterns_manager_with_detection):
    assert await _detected(sus_patterns_manager_with_detection, "SELECT/**/FROM/**/users")


@pytest.mark.asyncio
async def test_comment_inside_keyword_detected(sus_patterns_manager_with_detection):
    assert await _detected(sus_patterns_manager_with_detection, "SEL/**/ECT password FROM users")


@pytest.mark.asyncio
async def test_mysql_version_comment_detected(sus_patterns_manager_with_detection):
    assert await _detected(sus_patterns_manager_with_detection, "1' /*!50000OR*/ '1'='1")


@pytest.mark.asyncio
async def test_quote_flanked_comment_detected(sus_patterns_manager_with_detection):
    assert await _detected(sus_patterns_manager_with_detection, "1'/**/OR/**/'1'='1")


@pytest.mark.asyncio
async def test_benign_css_comment_not_flagged(sus_patterns_manager_with_detection):
    assert not await _detected(sus_patterns_manager_with_detection, "color: red; /* main theme */ font-size: 14px")


@pytest.mark.asyncio
async def test_stacked_ddl_detected(sus_patterns_manager_with_detection):
    assert await _detected(sus_patterns_manager_with_detection, "'; DROP TABLE users;--")


@pytest.mark.asyncio
async def test_order_by_enumeration_detected(sus_patterns_manager_with_detection):
    assert await _detected(sus_patterns_manager_with_detection, "1' ORDER BY 1--")


@pytest.mark.asyncio
async def test_benign_order_prose_not_flagged(sus_patterns_manager_with_detection):
    assert not await _detected(sus_patterns_manager_with_detection, "please order by phone or email when you can")
