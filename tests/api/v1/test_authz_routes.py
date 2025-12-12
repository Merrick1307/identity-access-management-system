"""
Tests for app/api/v1/authz.py - Authorization routes.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import BackgroundTasks

from app.api.v1.authz import authorize
from app.models.authz import Authorize, Action
from app.core.jwt_utils import VerifiedTokenData


class TestAuthorizeEndpoint:
    """Tests for the authorize endpoint."""
    
    @pytest.fixture
    def mock_user_with_policy(self):
        """Create a mock user with policies."""
        return VerifiedTokenData(
            email="user@example.com",
            tenant_id="tenant-123",
            user_id="user-456",
            role="user",
            policy={
                "documents": Action.READ | Action.WRITE,
                "users": Action.READ
            },
            exp=None,
            iat=None
        )
    
    @pytest.fixture
    def mock_app_state(self, mock_db_connection):
        """Create mock app state."""
        mock_state = MagicMock()
        mock_state.state = MagicMock()
        mock_state.state.dbconnection = MagicMock()
        mock_state.state.dbconnection.acquire = MagicMock()
        mock_state.state.dbconnection.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_db_connection)
        mock_state.state.dbconnection.acquire.return_value.__aexit__ = AsyncMock()
        return mock_state
    
    @pytest.mark.asyncio
    async def test_authorize_fga_granted(self, mock_app_state, mock_audit_logger, mock_user_with_policy):
        """Test FGA authorization when permission is granted."""
        request = Authorize(
            action="read",
            resource="documents",
            conditions_to_check=None,
            grant_type="fga"
        )
        
        result = await authorize(
            request=request,
            app_state=mock_app_state,
            background_tasks=BackgroundTasks(),
            logger_obj=mock_audit_logger,
            user_object=mock_user_with_policy
        )
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_authorize_fga_denied(self, mock_app_state, mock_audit_logger, mock_user_with_policy):
        """Test FGA authorization when permission is denied."""
        request = Authorize(
            action="delete",
            resource="documents",
            conditions_to_check=None,
            grant_type="fga"
        )
        
        result = await authorize(
            request=request,
            app_state=mock_app_state,
            background_tasks=BackgroundTasks(),
            logger_obj=mock_audit_logger,
            user_object=mock_user_with_policy
        )
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_authorize_fga_resource_not_in_policy(self, mock_app_state, mock_audit_logger, mock_user_with_policy):
        """Test FGA authorization for resource not in policy."""
        request = Authorize(
            action="read",
            resource="reports",
            conditions_to_check=None,
            grant_type="fga"
        )
        
        result = await authorize(
            request=request,
            app_state=mock_app_state,
            background_tasks=BackgroundTasks(),
            logger_obj=mock_audit_logger,
            user_object=mock_user_with_policy
        )
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_authorize_fga_with_conditions(self, mock_app_state, mock_audit_logger, mock_user_with_policy, mock_db_connection):
        """Test FGA authorization with condition checking."""
        request = Authorize(
            action="read",
            resource="documents",
            grant_type="fga",
            check_condition=True,
            conditions_to_check={"validity_time": True, "department": "engineering"}
        )
        
        mock_db_connection.fetchval = AsyncMock(return_value={"department": "engineering"})
        
        with patch('app.core.authz.check_condition', new_callable=AsyncMock) as mock_check:
            mock_check.return_value = True
            
            result = await authorize(
                request=request,
                app_state=mock_app_state,
                background_tasks=BackgroundTasks(),
                logger_obj=mock_audit_logger,
                user_object=mock_user_with_policy
            )
            
            assert result is True
    
    @pytest.mark.asyncio
    async def test_authorize_logs_access_denied(self, mock_app_state, mock_audit_logger, mock_user_with_policy):
        """Test that denied access is logged."""
        request = Authorize(
            action="manage",
            resource="users",
            conditions_to_check=None,
            grant_type="fga"
        )
        
        result = await authorize(
            request=request,
            app_state=mock_app_state,
            background_tasks=BackgroundTasks(),
            logger_obj=mock_audit_logger,
            user_object=mock_user_with_policy
        )
        
        assert result is False
        mock_audit_logger.warning.assert_called()


class TestAuthorizeModel:
    """Tests for Authorize request model validation."""
    
    def test_authorize_defaults(self):
        """Test Authorize model defaults."""
        auth = Authorize(action="read", resource="documents", conditions_to_check=None)
        
        assert auth.grant_type == "fga"
        assert auth.check_condition is False
        assert auth.conditions_to_check is None
    
    def test_authorize_with_all_options(self):
        """Test Authorize with all options specified."""
        auth = Authorize(
            action="write",
            resource="reports",
            grant_type="fga",
            check_condition=True,
            conditions_to_check={"level": "confidential"}
        )
        
        assert auth.action == "write"
        assert auth.resource == "reports"
        assert auth.conditions_to_check["level"] == "confidential"
