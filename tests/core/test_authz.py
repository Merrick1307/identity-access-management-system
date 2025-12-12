"""
Tests for app/core/authz.py - Authorization utilities.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock
from fastapi import HTTPException

from app.core.authz import check_permission, check_role, check_condition, permission_map
from app.models.authz import Action


class TestCheckPermission:
    """Tests for check_permission function."""
    
    def test_check_permission_granted_single_action(self):
        """Test permission check with a single matching action."""
        user_policy = {"users": Action.READ | Action.WRITE}
        assert check_permission(user_policy, "read", "users") is True
        assert check_permission(user_policy, "write", "users") is True
    
    def test_check_permission_denied(self):
        """Test permission check when action is not allowed."""
        user_policy = {"users": Action.READ}
        assert check_permission(user_policy, "write", "users") is False
        assert check_permission(user_policy, "delete", "users") is False
    
    def test_check_permission_resource_not_in_policy(self):
        """Test permission check when resource is not in user policy."""
        user_policy = {"users": Action.READ}
        assert check_permission(user_policy, "read", "documents") is False
    
    def test_check_permission_empty_policy(self):
        """Test permission check with empty policy."""
        assert check_permission({}, "read", "users") is False
    
    def test_check_permission_all_actions(self):
        """Test permission check with all actions granted."""
        all_actions = sum(Action)
        user_policy = {"users": all_actions}
        
        for action_name in permission_map.keys():
            assert check_permission(user_policy, action_name, "users") is True
    
    def test_check_permission_case_insensitive(self):
        """Test that action names are case insensitive."""
        user_policy = {"users": Action.READ}
        assert check_permission(user_policy, "READ", "users") is True
        assert check_permission(user_policy, "Read", "users") is True
    
    def test_check_permission_invalid_action(self):
        """Test permission check with invalid action name."""
        user_policy = {"users": Action.READ}
        assert check_permission(user_policy, "invalid_action", "users") is False
    
    def test_check_permission_bitwise_combination(self):
        """Test permission check with specific bitwise combinations."""
        user_policy = {"documents": Action.READ | Action.EXPORT}
        
        assert check_permission(user_policy, "read", "documents") is True
        assert check_permission(user_policy, "export", "documents") is True
        assert check_permission(user_policy, "write", "documents") is False
        assert check_permission(user_policy, "delete", "documents") is False


class TestCheckRole:
    """Tests for check_role function."""
    
    def test_check_role_matching(self):
        """Test role check with matching role."""
        user_policy = {"role": "admin"}
        assert check_role(user_policy, "admin") is True
    
    def test_check_role_case_insensitive(self):
        """Test role check is case insensitive."""
        user_policy = {"role": "Admin"}
        assert check_role(user_policy, "admin") is True
        assert check_role(user_policy, "ADMIN") is True
    
    def test_check_role_mismatch_raises_exception(self):
        """Test role check raises HTTPException on mismatch."""
        user_policy = {"role": "user"}
        
        with pytest.raises(HTTPException) as exc_info:
            check_role(user_policy, "admin")
        
        assert exc_info.value.status_code == 401
        assert "Unauthorized role" in exc_info.value.detail


class TestCheckCondition:
    """Tests for check_condition function."""
    
    @pytest.mark.asyncio
    async def test_check_condition_validity_time_only(self, mock_db_connection):
        """Test condition check with only validity_time."""
        conditions_to_compare = {"validity_time": True}
        user_policy = {"documents": Action.READ}
        
        result = await check_condition(
            db=mock_db_connection,
            conditions_to_compare=conditions_to_compare,
            resource="documents",
            user_policy=user_policy,
            user_id="user-123",
            tenant_id="tenant-456"
        )
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_check_condition_resource_not_in_policy(self, mock_db_connection):
        """Test condition check when resource is not in user policy."""
        conditions_to_compare = {"validity_time": True}
        user_policy = {"users": Action.READ}
        
        result = await check_condition(
            db=mock_db_connection,
            conditions_to_compare=conditions_to_compare,
            resource="documents",
            user_policy=user_policy,
            user_id="user-123",
            tenant_id="tenant-456"
        )
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_check_condition_with_additional_conditions(self, mock_db_connection):
        """Test condition check with additional conditions from DB."""
        conditions_to_compare = {"validity_time": True, "department": "engineering"}
        user_policy = {"documents": Action.READ}
        
        mock_db_connection.fetchval = AsyncMock(return_value={"department": "engineering"})
        
        result = await check_condition(
            db=mock_db_connection,
            conditions_to_compare=conditions_to_compare,
            resource="documents",
            user_policy=user_policy,
            user_id="user-123",
            tenant_id="tenant-456"
        )
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_check_condition_fails_when_conditions_not_met(self, mock_db_connection):
        """Test condition check raises exception when conditions not met."""
        conditions_to_compare = {"validity_time": True, "department": "engineering"}
        user_policy = {"documents": Action.READ}
        
        mock_db_connection.fetchval = AsyncMock(return_value={"department": "sales"})
        
        with pytest.raises(HTTPException) as exc_info:
            await check_condition(
                db=mock_db_connection,
                conditions_to_compare=conditions_to_compare,
                resource="documents",
                user_policy=user_policy,
                user_id="user-123",
                tenant_id="tenant-456"
            )
        
        assert exc_info.value.status_code == 401
        assert "condition not satisfied" in exc_info.value.detail


class TestPermissionMap:
    """Tests for permission_map constant."""
    
    def test_permission_map_contains_all_actions(self):
        """Test that permission_map contains all defined actions."""
        expected_actions = [
            'read', 'write', 'delete', 'approve', 'reject',
            'execute', 'assign', 'manage', 'export', 'import',
            'activate', 'archive'
        ]
        
        for action in expected_actions:
            assert action in permission_map
    
    def test_permission_map_values_are_action_flags(self):
        """Test that all permission_map values are Action IntFlags."""
        for action_name, action_value in permission_map.items():
            assert isinstance(action_value, Action)
