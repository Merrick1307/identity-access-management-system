"""
Tests for app/services/session_service.py - Session management service.
"""
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock
import orjson

from app.services.session_service import (
    create_session,
    get_active_sessions,
    revoke_session,
    revoke_all_sessions,
    cleanup_expired_sessions,
    get_all_tenant_sessions,
    admin_revoke_session,
    admin_bulk_revoke_sessions
)


class TestCreateSession:
    """Tests for create_session function."""
    
    @pytest.mark.asyncio
    async def test_create_session_basic(self, mock_db_connection):
        """Test creating a basic session."""
        mock_db_connection.execute = AsyncMock()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        await create_session(
            db=mock_db_connection,
            jti="user-123-1234567890",
            user_id="user-123",
            tenant_id="tenant-456",
            expires_at=expires_at
        )
        
        mock_db_connection.execute.assert_called_once()
        call_args = mock_db_connection.execute.call_args
        assert "INSERT INTO user_sessions" in call_args[0][0]
        assert call_args[0][1] == "user-123-1234567890"
    
    @pytest.mark.asyncio
    async def test_create_session_with_device_info(self, mock_db_connection):
        """Test creating session with device info."""
        mock_db_connection.execute = AsyncMock()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        device_info = {"user_agent": "Mozilla/5.0", "browser": "Chrome"}
        
        await create_session(
            db=mock_db_connection,
            jti="user-123-1234567890",
            user_id="user-123",
            tenant_id="tenant-456",
            expires_at=expires_at,
            ip_address="192.168.1.1",
            device_info=device_info
        )
        
        call_args = mock_db_connection.execute.call_args
        assert call_args[0][5] == "192.168.1.1"
    
    @pytest.mark.asyncio
    async def test_create_session_handles_conflict(self, mock_db_connection):
        """Test that create_session handles duplicate JTI gracefully."""
        mock_db_connection.execute = AsyncMock()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        await create_session(
            db=mock_db_connection,
            jti="duplicate-jti",
            user_id="user-123",
            tenant_id="tenant-456",
            expires_at=expires_at
        )
        
        assert "ON CONFLICT (jti) DO NOTHING" in mock_db_connection.execute.call_args[0][0]


class TestGetActiveSessions:
    """Tests for get_active_sessions function."""
    
    @pytest.mark.asyncio
    async def test_get_active_sessions_returns_list(self, mock_db_connection):
        """Test getting active sessions returns formatted list."""
        mock_rows = [
            {
                "jti": "session-1",
                "device_info": '{"browser": "Chrome"}',
                "ip_address": "192.168.1.1",
                "created_at": datetime.now(timezone.utc),
                "expires_at": datetime.now(timezone.utc) + timedelta(hours=1)
            },
            {
                "jti": "session-2",
                "device_info": None,
                "ip_address": None,
                "created_at": datetime.now(timezone.utc),
                "expires_at": datetime.now(timezone.utc) + timedelta(hours=1)
            }
        ]
        mock_db_connection.fetch = AsyncMock(return_value=mock_rows)
        
        sessions = await get_active_sessions(
            db=mock_db_connection,
            user_id="user-123",
            tenant_id="tenant-456"
        )
        
        assert len(sessions) == 2
        assert sessions[0]["jti"] == "session-1"
        assert sessions[0]["device_info"] == {"browser": "Chrome"}
        assert sessions[1]["device_info"] is None
    
    @pytest.mark.asyncio
    async def test_get_active_sessions_empty(self, mock_db_connection):
        """Test getting active sessions when none exist."""
        mock_db_connection.fetch = AsyncMock(return_value=[])
        
        sessions = await get_active_sessions(
            db=mock_db_connection,
            user_id="user-123",
            tenant_id="tenant-456"
        )
        
        assert sessions == []


class TestRevokeSession:
    """Tests for revoke_session function."""
    
    @pytest.mark.asyncio
    async def test_revoke_session_success(self, mock_db_connection, mock_revocation_manager):
        """Test successfully revoking a session."""
        mock_db_connection.execute = AsyncMock(return_value="UPDATE 1")
        
        result = await revoke_session(
            db=mock_db_connection,
            revocation_manager=mock_revocation_manager,
            jti="session-to-revoke",
            user_id="user-123",
            tenant_id="tenant-456",
            reason="manual_logout"
        )
        
        assert result is True
        mock_revocation_manager.revoke_token.assert_called_once_with(
            "session-to-revoke", "user-123", "tenant-456", "manual_logout"
        )
    
    @pytest.mark.asyncio
    async def test_revoke_session_not_found(self, mock_db_connection, mock_revocation_manager):
        """Test revoking non-existent session."""
        mock_db_connection.execute = AsyncMock(return_value="UPDATE 0")
        
        result = await revoke_session(
            db=mock_db_connection,
            revocation_manager=mock_revocation_manager,
            jti="nonexistent-session",
            user_id="user-123",
            tenant_id="tenant-456"
        )
        
        assert result is False
        mock_revocation_manager.revoke_token.assert_not_called()


class TestRevokeAllSessions:
    """Tests for revoke_all_sessions function."""
    
    @pytest.mark.asyncio
    async def test_revoke_all_sessions(self, mock_db_connection, mock_revocation_manager, mock_audit_logger):
        """Test revoking all sessions for a user."""
        mock_rows = [
            {"jti": "session-1"},
            {"jti": "session-2"},
            {"jti": "session-3"}
        ]
        mock_db_connection.fetch = AsyncMock(return_value=mock_rows)
        mock_db_connection.execute = AsyncMock()
        
        count = await revoke_all_sessions(
            db=mock_db_connection,
            revocation_manager=mock_revocation_manager,
            user_id="user-123",
            tenant_id="tenant-456",
            logger=mock_audit_logger,
            reason="bulk_logout"
        )
        
        assert count == 3
        mock_revocation_manager.revoke_user_tokens.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_revoke_all_sessions_with_exclude(self, mock_db_connection, mock_revocation_manager, mock_audit_logger):
        """Test revoking all sessions except current."""
        mock_rows = [{"jti": "session-2"}, {"jti": "session-3"}]
        mock_db_connection.fetch = AsyncMock(return_value=mock_rows)
        mock_db_connection.execute = AsyncMock()
        
        count = await revoke_all_sessions(
            db=mock_db_connection,
            revocation_manager=mock_revocation_manager,
            user_id="user-123",
            tenant_id="tenant-456",
            logger=mock_audit_logger,
            reason="logout_others",
            exclude_jti="session-1"
        )
        
        assert count == 2
    
    @pytest.mark.asyncio
    async def test_revoke_all_sessions_none_to_revoke(self, mock_db_connection, mock_revocation_manager, mock_audit_logger):
        """Test when there are no sessions to revoke."""
        mock_db_connection.fetch = AsyncMock(return_value=[])
        
        count = await revoke_all_sessions(
            db=mock_db_connection,
            revocation_manager=mock_revocation_manager,
            user_id="user-123",
            tenant_id="tenant-456",
            logger=mock_audit_logger
        )
        
        assert count == 0


class TestCleanupExpiredSessions:
    """Tests for cleanup_expired_sessions function."""
    
    @pytest.mark.asyncio
    async def test_cleanup_expired_sessions(self, mock_db_connection):
        """Test cleaning up expired sessions."""
        mock_db_connection.execute = AsyncMock(return_value="DELETE 15")
        
        count = await cleanup_expired_sessions(mock_db_connection)
        
        assert count == 15
        assert "DELETE FROM user_sessions" in mock_db_connection.execute.call_args[0][0]
    
    @pytest.mark.asyncio
    async def test_cleanup_expired_sessions_none_to_delete(self, mock_db_connection):
        """Test cleanup when no expired sessions."""
        mock_db_connection.execute = AsyncMock(return_value="DELETE 0")
        
        count = await cleanup_expired_sessions(mock_db_connection)
        
        assert count == 0


class TestGetAllTenantSessions:
    """Tests for get_all_tenant_sessions function."""
    
    @pytest.mark.asyncio
    async def test_get_all_tenant_sessions_active_only(self, mock_db_connection):
        """Test getting all active sessions for a tenant."""
        mock_rows = [
            {
                "jti": "session-1",
                "user_id": "user-1",
                "user_email": "user1@example.com",
                "device_info": None,
                "ip_address": "192.168.1.1",
                "created_at": datetime.now(timezone.utc),
                "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
                "status": "active"
            }
        ]
        mock_db_connection.fetch = AsyncMock(return_value=mock_rows)
        
        sessions = await get_all_tenant_sessions(
            db=mock_db_connection,
            tenant_id="tenant-456",
            include_expired=False
        )
        
        assert len(sessions) == 1
        assert sessions[0]["user_email"] == "user1@example.com"
    
    @pytest.mark.asyncio
    async def test_get_all_tenant_sessions_include_expired(self, mock_db_connection):
        """Test getting all sessions including expired."""
        mock_db_connection.fetch = AsyncMock(return_value=[])
        
        await get_all_tenant_sessions(
            db=mock_db_connection,
            tenant_id="tenant-456",
            include_expired=True
        )
        
        call_query = mock_db_connection.fetch.call_args[0][0]
        assert "revoked_at" in call_query or "expired" in call_query


class TestAdminRevokeSession:
    """Tests for admin_revoke_session function."""
    
    @pytest.mark.asyncio
    async def test_admin_revoke_session_success(self, mock_db_connection, mock_revocation_manager):
        """Test admin successfully revoking a session."""
        mock_db_connection.fetchrow = AsyncMock(return_value={"user_id": "user-123"})
        mock_db_connection.execute = AsyncMock(return_value="UPDATE 1")
        
        result = await admin_revoke_session(
            db=mock_db_connection,
            revocation_manager=mock_revocation_manager,
            jti="session-to-revoke",
            tenant_id="tenant-456",
            reason="admin_revoke"
        )
        
        assert result is True
        mock_revocation_manager.revoke_token.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_admin_revoke_session_not_found(self, mock_db_connection, mock_revocation_manager):
        """Test admin revoking non-existent session."""
        mock_db_connection.fetchrow = AsyncMock(return_value=None)
        
        result = await admin_revoke_session(
            db=mock_db_connection,
            revocation_manager=mock_revocation_manager,
            jti="nonexistent",
            tenant_id="tenant-456"
        )
        
        assert result is False


class TestAdminBulkRevokeSessions:
    """Tests for admin_bulk_revoke_sessions function."""
    
    @pytest.mark.asyncio
    async def test_admin_bulk_revoke_sessions(self, mock_db_connection, mock_revocation_manager, mock_audit_logger):
        """Test admin bulk revoking sessions."""
        mock_rows = [
            {"jti": "session-1", "user_id": "user-1"},
            {"jti": "session-2", "user_id": "user-1"},
            {"jti": "session-3", "user_id": "user-2"}
        ]
        mock_db_connection.fetch = AsyncMock(return_value=mock_rows)
        mock_db_connection.execute = AsyncMock()
        
        count = await admin_bulk_revoke_sessions(
            db=mock_db_connection,
            revocation_manager=mock_revocation_manager,
            jtis=["session-1", "session-2", "session-3"],
            tenant_id="tenant-456",
            logger=mock_audit_logger,
            reason="admin_bulk_revoke"
        )
        
        assert count == 3
        assert mock_revocation_manager.revoke_user_tokens.call_count == 2
    
    @pytest.mark.asyncio
    async def test_admin_bulk_revoke_empty_list(self, mock_db_connection, mock_revocation_manager, mock_audit_logger):
        """Test admin bulk revoke with empty JTI list."""
        count = await admin_bulk_revoke_sessions(
            db=mock_db_connection,
            revocation_manager=mock_revocation_manager,
            jtis=[],
            tenant_id="tenant-456",
            logger=mock_audit_logger
        )
        
        assert count == 0
