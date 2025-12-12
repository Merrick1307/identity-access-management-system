"""
Tests for app/core/token_revocation.py - Token revocation with Redis Streams and Bloom filters.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import redis.asyncio as redis

from app.core.token_revocation import (
    RevocationEvent,
    TokenRevocationManager,
    STREAM_NAME,
    CONSUMER_GROUP,
    init_revocation_manager,
    shutdown_revocation_manager,
    get_revocation_manager
)


class TestRevocationEvent:
    """Tests for RevocationEvent dataclass."""
    
    def test_revocation_event_creation(self):
        """Test creating a RevocationEvent."""
        event = RevocationEvent(
            jti="user-123-1234567890",
            user_id="user-123",
            tenant_id="tenant-456",
            reason="logout",
            timestamp="2024-01-15T10:30:00Z"
        )
        
        assert event.jti == "user-123-1234567890"
        assert event.user_id == "user-123"
        assert event.tenant_id == "tenant-456"
        assert event.reason == "logout"


class TestTokenRevocationManager:
    """Tests for TokenRevocationManager class."""
    
    @pytest.fixture
    def revocation_manager(self, mock_redis, mock_bloom_filter):
        """Create a TokenRevocationManager instance."""
        return TokenRevocationManager(
            redis_client=mock_redis,
            bloom_filter=mock_bloom_filter,
            worker_id="test-worker"
        )
    
    @pytest.mark.asyncio
    async def test_initialize_creates_consumer_group(self, revocation_manager, mock_redis):
        """Test that initialize creates consumer group."""
        mock_redis.xgroup_create = AsyncMock()
        mock_redis.xrange = AsyncMock(return_value=[])
        
        await revocation_manager.initialize()
        
        mock_redis.xgroup_create.assert_called_once()
        call_args = mock_redis.xgroup_create.call_args
        assert call_args[0][0] == STREAM_NAME
        assert call_args[0][1] == CONSUMER_GROUP
        
        await revocation_manager.shutdown()
    
    @pytest.mark.asyncio
    async def test_initialize_handles_existing_group(self, revocation_manager, mock_redis):
        """Test that initialize handles already existing consumer group."""
        mock_redis.xgroup_create = AsyncMock(
            side_effect=redis.ResponseError("BUSYGROUP Consumer Group name already exists")
        )
        mock_redis.xrange = AsyncMock(return_value=[])
        
        await revocation_manager.initialize()
        
        assert revocation_manager._running is True
        
        await revocation_manager.shutdown()
    
    @pytest.mark.asyncio
    async def test_load_existing_revocations(self, revocation_manager, mock_redis, mock_bloom_filter):
        """Test loading existing revocations into bloom filter."""
        existing_entries = [
            ("entry-1", {"jti": "token-1"}),
            ("entry-2", {"jti": "token-2"}),
            ("entry-3", {"jti": "token-3"})
        ]
        mock_redis.xrange = AsyncMock(side_effect=[existing_entries, []])
        mock_redis.xgroup_create = AsyncMock()
        
        await revocation_manager.initialize()
        
        assert mock_bloom_filter.add.call_count == 3
        
        await revocation_manager.shutdown()
    
    @pytest.mark.asyncio
    async def test_revoke_token_adds_to_bloom(self, revocation_manager, mock_bloom_filter, mock_redis):
        """Test that revoke_token adds JTI to bloom filter."""
        mock_redis.xadd = AsyncMock()
        
        result = await revocation_manager.revoke_token(
            jti="token-123",
            user_id="user-456",
            tenant_id="tenant-789",
            reason="logout"
        )
        
        assert result is True
        mock_bloom_filter.add.assert_called_with("token-123")
    
    @pytest.mark.asyncio
    async def test_revoke_token_publishes_to_stream(self, revocation_manager, mock_redis):
        """Test that revoke_token publishes to Redis stream."""
        mock_redis.xadd = AsyncMock()
        
        await revocation_manager.revoke_token(
            jti="token-123",
            user_id="user-456",
            tenant_id="tenant-789",
            reason="password_change"
        )
        
        mock_redis.xadd.assert_called_once()
        call_args = mock_redis.xadd.call_args
        assert call_args[0][0] == STREAM_NAME
        assert call_args[0][1]["jti"] == "token-123"
        assert call_args[0][1]["reason"] == "password_change"
    
    @pytest.mark.asyncio
    async def test_revoke_token_handles_redis_error(self, revocation_manager, mock_redis, mock_bloom_filter):
        """Test that revoke_token handles Redis errors gracefully."""
        mock_redis.xadd = AsyncMock(side_effect=Exception("Redis connection error"))
        
        result = await revocation_manager.revoke_token(
            jti="token-123",
            user_id="user-456",
            tenant_id="tenant-789",
            reason="logout"
        )
        
        assert result is False
        mock_bloom_filter.add.assert_called_with("token-123")
    
    @pytest.mark.asyncio
    async def test_revoke_user_tokens_bulk(self, revocation_manager, mock_redis):
        """Test revoking multiple tokens for a user."""
        mock_redis.xadd = AsyncMock()
        jtis = ["token-1", "token-2", "token-3"]
        
        count = await revocation_manager.revoke_user_tokens(
            user_id="user-123",
            tenant_id="tenant-456",
            jtis=jtis,
            reason="logout_all"
        )
        
        assert count == 3
        assert mock_redis.xadd.call_count == 3
    
    def test_is_revoked_checks_bloom_filter(self, revocation_manager, mock_bloom_filter):
        """Test that is_revoked checks the bloom filter."""
        mock_bloom_filter.__contains__ = MagicMock(return_value=True)
        
        result = revocation_manager.is_revoked("token-123")
        
        assert result is True
        mock_bloom_filter.__contains__.assert_called_with("token-123")
    
    def test_is_revoked_returns_false_for_unknown_token(self, revocation_manager, mock_bloom_filter):
        """Test that is_revoked returns False for unknown tokens."""
        mock_bloom_filter.__contains__ = MagicMock(return_value=False)
        
        result = revocation_manager.is_revoked("unknown-token")
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_shutdown_stops_consumer(self, revocation_manager, mock_redis):
        """Test that shutdown stops the consumer task."""
        mock_redis.xgroup_create = AsyncMock()
        mock_redis.xrange = AsyncMock(return_value=[])
        mock_redis.xreadgroup = AsyncMock(return_value=[])
        
        await revocation_manager.initialize()
        assert revocation_manager._running is True
        
        await revocation_manager.shutdown()
        
        assert revocation_manager._running is False
    
    @pytest.mark.asyncio
    async def test_get_stats(self, revocation_manager, mock_redis):
        """Test getting revocation stats."""
        mock_redis.xinfo_stream = AsyncMock(return_value={"length": 1500})
        
        stats = await revocation_manager.get_stats()
        
        assert stats["worker_id"] == "test-worker"
        assert stats["stream_length"] == 1500


class TestModuleFunctions:
    """Tests for module-level functions."""
    
    @pytest.mark.asyncio
    async def test_init_revocation_manager(self, mock_redis, mock_bloom_filter):
        """Test init_revocation_manager function."""
        mock_redis.xgroup_create = AsyncMock()
        mock_redis.xrange = AsyncMock(return_value=[])
        mock_redis.xreadgroup = AsyncMock(return_value=[])
        
        app_state = MagicMock()
        app_state.redis = mock_redis
        app_state.bloom_filter = mock_bloom_filter
        
        manager = await init_revocation_manager(app_state)
        
        assert manager is not None
        assert hasattr(app_state, 'revocation_manager')
        
        await manager.shutdown()
    
    def test_get_revocation_manager_raises_when_not_initialized(self):
        """Test that get_revocation_manager raises when not initialized."""
        import app.core.token_revocation as module
        original = module._revocation_manager
        module._revocation_manager = None
        
        try:
            with pytest.raises(RuntimeError) as exc_info:
                get_revocation_manager()
            
            assert "not initialized" in str(exc_info.value)
        finally:
            module._revocation_manager = original
