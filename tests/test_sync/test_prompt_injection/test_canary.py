from guard_core.sync.prompt_injection.canary import CanaryManager


class TestCanaryManager:
    def test_generate_canary(self) -> None:
        manager = CanaryManager(use_redis=False)
        canary = manager.generate_canary()
        assert canary.startswith("GUARD_CANARY_")
        assert len(canary) > 20

    def test_unique_canaries(self) -> None:
        manager = CanaryManager(use_redis=False)
        c1 = manager.generate_canary()
        c2 = manager.generate_canary()
        assert c1 != c2

    def test_inject_canary(self) -> None:
        manager = CanaryManager(use_redis=False)
        canary = "GUARD_CANARY_test123"
        result = manager.inject_canary("You are a helpful assistant.", canary)
        assert canary in result
        assert "NEVER" in result
        assert "You are a helpful assistant." in result

    def test_verify_output_safe(self) -> None:
        manager = CanaryManager(use_redis=False)
        canary = "GUARD_CANARY_abc123"
        assert manager.verify_output("Here is my response about cooking.", canary)

    def test_verify_output_leaked(self) -> None:
        manager = CanaryManager(use_redis=False)
        canary = "GUARD_CANARY_abc123"
        assert not manager.verify_output(f"The canary is {canary}", canary)

    def test_verify_output_case_insensitive(self) -> None:
        manager = CanaryManager(use_redis=False)
        canary = "GUARD_CANARY_abc123"
        assert not manager.verify_output("guard_canary_abc123 leaked", canary)

    def test_verify_output_partial_prefix(self) -> None:
        manager = CanaryManager(use_redis=False)
        canary = "GUARD_CANARY_abc12345"
        assert not manager.verify_output("GUARD_CA was mentioned", canary)

    def test_verify_output_partial_suffix(self) -> None:
        manager = CanaryManager(use_redis=False)
        canary = "GUARD_CANARY_abc12345"
        # Last 8 chars of canary is "abc12345"
        assert not manager.verify_output("the token abc12345 was found", canary)

    def test_verify_output_empty(self) -> None:
        manager = CanaryManager(use_redis=False)
        assert manager.verify_output("", "GUARD_CANARY_test")
        assert manager.verify_output("test", "")

    def test_is_canary_valid_in_memory(self) -> None:
        manager = CanaryManager(use_redis=False)
        canary = manager.generate_canary()
        assert manager.is_canary_valid(canary)

    def test_is_canary_invalid(self) -> None:
        manager = CanaryManager(use_redis=False)
        assert not manager.is_canary_valid("GUARD_CANARY_nonexistent")

    def test_cleanup_expired(self) -> None:
        manager = CanaryManager(use_redis=False, ttl_seconds=0)
        manager.generate_canary()
        manager.generate_canary()
        removed = manager.cleanup_expired()
        assert removed >= 2

    def test_memory_auto_cleanup(self) -> None:
        manager = CanaryManager(use_redis=False, ttl_seconds=0)
        # Generate many canaries to trigger auto-cleanup
        for _ in range(1002):
            manager.generate_canary()
        # Should not have more than 1000 + small buffer
        assert len(manager._memory_canaries) <= 1001

    def test_generate_with_session_id(self) -> None:
        manager = CanaryManager(use_redis=False)
        canary = manager.generate_canary(session_id="user123")
        assert canary.startswith("GUARD_CANARY_")

    def test_redis_fallback_no_client(self) -> None:
        """When redis_manager has no client, falls back gracefully."""
        manager = CanaryManager(redis_manager=None, use_redis=False)
        canary = manager.generate_canary()
        assert manager.is_canary_valid(canary)

    def test_cleanup_with_redis_returns_zero(self) -> None:
        """Redis handles its own cleanup."""

        class FakeRedis:
            redis_client = None

        manager = CanaryManager(redis_manager=FakeRedis(), use_redis=True)
        assert manager.cleanup_expired() == 0

    def test_redis_store_and_validate(self) -> None:
        """Test Redis storage path with mock."""
        from unittest.mock import MagicMock

        mock_redis = MagicMock()
        mock_redis.redis_client = MagicMock()
        mock_redis.redis_client.exists.return_value = True

        manager = CanaryManager(redis_manager=mock_redis, use_redis=True)
        canary = manager.generate_canary(session_id="test")
        mock_redis.redis_client.setex.assert_called_once()
        assert manager.is_canary_valid(canary)

    def test_redis_invalid_canary(self) -> None:
        """Redis returns False for nonexistent canary."""
        from unittest.mock import MagicMock

        mock_redis = MagicMock()
        mock_redis.redis_client = MagicMock()
        mock_redis.redis_client.exists.return_value = False

        manager = CanaryManager(redis_manager=mock_redis, use_redis=True)
        assert not manager.is_canary_valid("GUARD_CANARY_fake")

    def test_in_memory_expired_canary(self) -> None:
        """Expired canary in memory returns False and is cleaned up."""
        manager = CanaryManager(use_redis=False, ttl_seconds=0)
        canary = manager.generate_canary()
        # TTL is 0, so immediately expired
        assert not manager.is_canary_valid(canary)
        # Should have been removed
        assert canary not in manager._memory_canaries

    def test_redis_store_no_client(self) -> None:
        """When redis_client is None, store silently fails."""

        class NoClient:
            redis_client = None

        manager = CanaryManager(redis_manager=NoClient(), use_redis=True)
        canary = manager.generate_canary()
        # No crash, but canary not valid since no storage
        assert not manager.is_canary_valid(canary)
