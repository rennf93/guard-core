from guard_core.sync.core.checks._verifier import resolve_verifier_result


def test_resolve_verifier_result_returns_plain_value() -> None:
    assert resolve_verifier_result("principal") == "principal"
