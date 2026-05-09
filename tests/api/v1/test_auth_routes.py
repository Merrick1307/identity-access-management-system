"""
Tests for app/api/v1/auth.py - Authentication routes.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException

from app.api.v1.auth import (
    get_token,
    get_session_device_details,
    logout_session,
    refresh_session,
    list_my_sessions,
    logout_all_sessions,
    logout_other_sessions,
    revoke_specific_session,
    list_all_tenant_sessions,
    list_user_sessions,
    admin_bulk_revoke,
    admin_revoke_user_sessions
)


class TestGetToken:
    """Tests for get_token endpoint."""
    
    @pytest.mark.asyncio
    async def test_get_token_success(self, mock_db_connection, mock_audit_logger):
        """Test successful token generation."""
        mock_request = MagicMock()
        mock_request.headers.get.side_effect = lambda x, default=None: {
            "X-TENANT-ID": "tenant-123",
            "User-Agent": "TestClient/1.0"
        }.get(x, default)
        mock_request.client.host = "127.0.0.1"
        
        mock_auth = MagicMock()
        mock_auth.email = "user@example.com"
        mock_auth.password = "password123"
        
        mock_background_tasks = MagicMock()
        
        with patch('app.api.v1.auth.authenticate', new_callable=AsyncMock) as mock_auth_fn:
            mock_auth_fn.return_value = "valid.jwt.token"
            
            response = await get_token(
                request=mock_request,
                auth=mock_auth,
                background_tasks=mock_background_tasks,
                logger_obj=mock_audit_logger,
                db=mock_db_connection
            )
            
            assert response.status_code == 200


class TestLogoutSession:
    """Tests for logout_session endpoint."""
    
    @pytest.mark.asyncio
    async def test_logout_session_success(self, mock_db_connection, mock_audit_logger, mock_revocation_manager):
        """Test successful logout."""
        mock_request = MagicMock()
        mock_request.headers.get.return_value = "Bearer valid.jwt.token"
        
        with patch('app.api.v1.auth.logout', new_callable=AsyncMock) as mock_logout:
            mock_logout.return_value = MagicMock(status_code=200)
            
            response = await logout_session(
                request=mock_request,
                logger_obj=mock_audit_logger,
                revocation_manager=mock_revocation_manager,
                db=mock_db_connection
            )
            
            mock_logout.assert_called_once()


class TestListMySessions:
    """Tests for list_my_sessions endpoint."""
    
    @pytest.mark.asyncio
    async def test_list_my_sessions_success(self, mock_db_connection):
        """Test listing user's sessions."""
        from app.core.jwt_utils import VerifiedTokenData
        from app.models.responses import PaginationInfo, SessionInfo, SessionListResponse
        
        mock_user = VerifiedTokenData(
            email="user@example.com",
            tenant_id="tenant-123",
            user_id="user-456",
            role="user",
            policy={},
            exp=None,
            iat=None,
            aud="hexshare-client"
        )
        
        with patch('app.api.v1.auth.get_active_sessions', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = SessionListResponse(
                sessions=[SessionInfo(jti="session-1", has_device_info=False, ip_address="127.0.0.1")],
                pagination=PaginationInfo(page=1, page_size=20, total_items=1, total_pages=1)
            )
            
            response = await list_my_sessions(user=mock_user, db=mock_db_connection)
            
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_get_session_device_details_success(self, mock_db_connection):
        """Test fetching device info for a session."""
        from app.core.jwt_utils import VerifiedTokenData
        from app.models.responses import SessionDeviceInfoResponse

        mock_user = VerifiedTokenData(
            email="admin@example.com",
            tenant_id="tenant-123",
            user_id="admin-456",
            role="admin",
            policy={},
            exp=None,
            iat=None,
            aud="hexshare-client"
        )

        with patch('app.api.v1.auth.get_session_device_info', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = SessionDeviceInfoResponse(
                jti="session-1",
                device_info={"user_agent": "Mozilla/5.0"}
            )

            response = await get_session_device_details(
                jti="session-1",
                user=mock_user,
                db=mock_db_connection
            )

            assert response.status_code == 200


class TestAdminSessionEndpoints:
    """Tests for admin session management endpoints."""
    
    @pytest.mark.asyncio
    async def test_list_all_tenant_sessions_admin_only(self, mock_db_connection):
        """Test that non-admin cannot list all sessions."""
        from app.core.jwt_utils import VerifiedTokenData
        from app.exceptions.http_error_module import HTTPError
        
        mock_user = VerifiedTokenData(
            email="user@example.com",
            tenant_id="tenant-123",
            user_id="user-456",
            role="user",
            policy={},
            exp=None,
            iat=None,
            aud="hexshare-client"
        )
        
        with pytest.raises((HTTPException, HTTPError)):
            await list_all_tenant_sessions(user=mock_user, db=mock_db_connection)
    
    @pytest.mark.asyncio
    async def test_list_all_tenant_sessions_admin_success(self, mock_db_connection):
        """Test admin can list all tenant sessions."""
        from app.core.jwt_utils import VerifiedTokenData
        from app.models.responses import PaginationInfo, TenantSessionInfo, TenantSessionListResponse
        
        mock_user = VerifiedTokenData(
            email="admin@example.com",
            tenant_id="tenant-123",
            user_id="admin-456",
            role="admin",
            policy={},
            exp=None,
            iat=None,
            aud="hexshare-client"
        )
        
        with patch('app.api.v1.auth.get_all_tenant_sessions', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = TenantSessionListResponse(
                sessions=[TenantSessionInfo(jti="session-1", user_id="user-1", user_email="user@example.com")],
                pagination=PaginationInfo(page=1, page_size=20, total_items=1, total_pages=1)
            )
            
            response = await list_all_tenant_sessions(user=mock_user, db=mock_db_connection)
            
            assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_admin_bulk_revoke_non_admin(self, mock_db_connection, mock_revocation_manager, mock_audit_logger):
        """Test that non-admin cannot bulk revoke."""
        from app.core.jwt_utils import VerifiedTokenData
        from app.models.auth import BulkRevokeRequest
        from app.exceptions.http_error_module import HTTPError
        
        mock_user = VerifiedTokenData(
            email="user@example.com",
            tenant_id="tenant-123",
            user_id="user-456",
            role="user",
            policy={},
            exp=None,
            iat=None,
            aud="hexshare-client"
        )
        
        request_data = BulkRevokeRequest(jtis=["jti-1", "jti-2"])
        
        with pytest.raises((HTTPException, HTTPError)):
            await admin_bulk_revoke(
                request_data=request_data,
                user=mock_user,
                db=mock_db_connection,
                revocation_manager=mock_revocation_manager,
                logger_obj=mock_audit_logger
            )
    
    @pytest.mark.asyncio
    async def test_admin_revoke_user_sessions(self, mock_db_connection, mock_revocation_manager, mock_audit_logger):
        """Test admin revoking all sessions for a user."""
        from app.core.jwt_utils import VerifiedTokenData
        
        mock_user = VerifiedTokenData(
            email="admin@example.com",
            tenant_id="tenant-123",
            user_id="admin-456",
            role="superadmin",
            policy={},
            exp=None,
            iat=None,
            aud="hexshare-client"
        )
        
        with patch('app.api.v1.auth.revoke_all_sessions', new_callable=AsyncMock) as mock_revoke:
            mock_revoke.return_value = 5
            
            response = await admin_revoke_user_sessions(
                user_id="target-user-789",
                user=mock_user,
                db=mock_db_connection,
                revocation_manager=mock_revocation_manager,
                logger_obj=mock_audit_logger
            )
            
            assert response.status_code == 200


class TestLogoutOtherSessions:
    """Tests for logout_other_sessions endpoint."""
    
    @pytest.mark.asyncio
    async def test_logout_other_sessions(self, mock_db_connection, mock_revocation_manager, mock_audit_logger):
        """Test logging out other sessions keeping current."""
        from app.core.jwt_utils import VerifiedTokenData
        import jwt
        from app.core.config import JWT_SECRET
        
        payload = {"sub": "user@example.com", "user_id": "user-123"}
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256", headers={"jti": "current-jti"})
        
        mock_request = MagicMock()
        mock_request.headers.get.return_value = f"Bearer {token}"
        
        mock_user = VerifiedTokenData(
            email="user@example.com",
            tenant_id="tenant-123",
            user_id="user-456",
            role="user",
            policy={},
            exp=None,
            iat=None,
            aud="hexshare-client"
        )
        
        with patch('app.api.v1.auth.revoke_all_sessions', new_callable=AsyncMock) as mock_revoke:
            mock_revoke.return_value = 3
            
            response = await logout_other_sessions(
                request=mock_request,
                user=mock_user,
                db=mock_db_connection,
                revocation_manager=mock_revocation_manager,
                logger_obj=mock_audit_logger
            )
            
            assert response.status_code == 200
