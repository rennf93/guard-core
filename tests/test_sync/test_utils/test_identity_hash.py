from guard_core.sync._utils.identity_hash import _hash_identity_segment


def test_hash_identity_segment_is_deterministic() -> None:
    assert _hash_identity_segment("value") == _hash_identity_segment("value")


def test_hash_identity_segment_differs_for_different_input() -> None:
    assert _hash_identity_segment("a") != _hash_identity_segment("b")


def test_hash_identity_segment_never_contains_the_raw_input() -> None:
    secret = "password=hunter2topsecretvalue"
    assert secret not in _hash_identity_segment(secret)
