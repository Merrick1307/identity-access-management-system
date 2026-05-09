"""
Tests for app/services/policy_service.py - Policy management service.
"""
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
import orjson
from fastapi import HTTPException

from app.services.policy_service import (
    get_user_policies,
    get_policy_by_id,
    create_policy,
    update_policy,
    delete_policy,
    assign_policy_to_user,
    bulk_assign_policy,
    revoke_policy_from_user,
    get_all_tenant_policies,
    create_tenant_policy_template,
    get_tenant_policy_templates,
    get_tenant_policy_template_by_id,
    update_tenant_policy_template,
    delete_tenant_policy_template,
    assign_template_to_user
)
from app.models.policy import PolicyCreate, PolicyUpdate, AssignPolicyRequest


class TestGetUserPolicies:
    """Tests for get_user_policies function."""
    
    @pytest.mark.asyncio
    async def test_get_user_policies_returns_list(self, mock_db_connection, mock_audit_logger):
        """Test getting user policies returns formatted list."""
        mock_rows = [
            {
                "policy_id": "policy-1",
                "user_id": "user-123",
                "tenant_id": "tenant-456",
                "policy": orjson.dumps({"resource": "users", "actions": ["read"]}).decode(),
                "created_at": datetime.now(timezone.utc),
                "last_modified": None
            }
        ]
        mock_db_connection.fetch = AsyncMock(return_value=mock_rows)
        
        policies = await get_user_policies(
            db=mock_db_connection,
            tenant_id="tenant-456",
            user_id="user-123",
            logger=mock_audit_logger
        )
        
        assert len(policies) == 1
        assert policies[0].policy_id == "policy-1"
        assert policies[0].resource == "users"
        assert policies[0].actions == ["read"]
    
    @pytest.mark.asyncio
    async def test_get_user_policies_empty(self, mock_db_connection, mock_audit_logger):
        """Test getting policies when user has none."""
        mock_db_connection.fetch = AsyncMock(return_value=[])
        
        policies = await get_user_policies(
            db=mock_db_connection,
            tenant_id="tenant-456",
            user_id="user-123",
            logger=mock_audit_logger
        )
        
        assert policies == []


class TestGetPolicyById:
    """Tests for get_policy_by_id function."""
    
    @pytest.mark.asyncio
    async def test_get_policy_by_id_found(self, mock_db_connection, mock_audit_logger):
        """Test getting existing policy by ID."""
        mock_row = {
            "policy_id": "policy-1",
            "user_id": "user-123",
            "tenant_id": "tenant-456",
            "policy": orjson.dumps({"resource": "documents", "actions": ["read", "write"]}).decode(),
            "created_at": datetime.now(timezone.utc),
            "last_modified": None
        }
        mock_db_connection.fetchrow = AsyncMock(return_value=mock_row)
        
        policy = await get_policy_by_id(
            db=mock_db_connection,
            tenant_id="tenant-456",
            user_id="user-123",
            policy_id="policy-1",
            logger=mock_audit_logger
        )
        
        assert policy is not None
        assert policy.policy_id == "policy-1"
        assert policy.resource == "documents"
    
    @pytest.mark.asyncio
    async def test_get_policy_by_id_not_found(self, mock_db_connection, mock_audit_logger):
        """Test getting non-existent policy."""
        mock_db_connection.fetchrow = AsyncMock(return_value=None)
        
        policy = await get_policy_by_id(
            db=mock_db_connection,
            tenant_id="tenant-456",
            user_id="user-123",
            policy_id="nonexistent",
            logger=mock_audit_logger
        )
        
        assert policy is None


class TestCreatePolicy:
    """Tests for create_policy function."""
    
    @pytest.mark.asyncio
    async def test_create_policy_success(self, mock_db_connection, mock_audit_logger):
        """Test successfully creating a policy."""
        mock_db_connection.execute = AsyncMock(return_value="INSERT 0 1")
        
        policy_data = PolicyCreate(
            policy_id="new-policy",
            resource="reports",
            actions=["read", "export"]
        )
        
        result = await create_policy(
            db=mock_db_connection,
            tenant_id="tenant-456",
            user_id="user-123",
            policy=policy_data,
            logger=mock_audit_logger
        )
        
        assert result.policy_id == "new-policy"
        assert result.resource == "reports"
        assert result.actions == ["read", "export"]
        mock_audit_logger.audit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_policy_duplicate_raises_conflict(self, mock_db_connection, mock_audit_logger):
        """Test that creating duplicate policy raises HTTPException."""
        mock_db_connection.execute = AsyncMock(return_value="INSERT 0 0")
        
        policy_data = PolicyCreate(
            policy_id="existing-policy",
            resource="users",
            actions=["read"]
        )
        
        with pytest.raises(HTTPException) as exc_info:
            await create_policy(
                db=mock_db_connection,
                tenant_id="tenant-456",
                user_id="user-123",
                policy=policy_data,
                logger=mock_audit_logger
            )
        
        assert exc_info.value.status_code == 409
        assert "already exists" in exc_info.value.detail


class TestUpdatePolicy:
    """Tests for update_policy function."""
    
    @pytest.mark.asyncio
    async def test_update_policy_success(self, mock_db_connection, mock_audit_logger, mock_revocation_manager):
        """Test successfully updating a policy."""
        existing_row = {
            "policy_id": "policy-1",
            "user_id": "user-123",
            "tenant_id": "tenant-456",
            "policy": orjson.dumps({"resource": "users", "actions": ["read"]}).decode(),
            "created_at": datetime.now(timezone.utc),
            "last_modified": None
        }
        mock_db_connection.fetchrow = AsyncMock(return_value=existing_row)
        mock_db_connection.execute = AsyncMock()
        
        updates = PolicyUpdate(actions=["read", "write", "delete"])
        
        result = await update_policy(
            db=mock_db_connection,
            tenant_id="tenant-456",
            user_id="user-123",
            policy_id="policy-1",
            updates=updates,
            logger=mock_audit_logger,
            revocation_manager=mock_revocation_manager
        )
        
        assert set(result.actions) == {"read", "write", "delete"}
    
    @pytest.mark.asyncio
    async def test_update_policy_not_found(self, mock_db_connection, mock_audit_logger, mock_revocation_manager):
        """Test updating non-existent policy raises HTTPException."""
        mock_db_connection.fetchrow = AsyncMock(return_value=None)
        
        updates = PolicyUpdate(actions=["read"])
        
        with pytest.raises(HTTPException) as exc_info:
            await update_policy(
                db=mock_db_connection,
                tenant_id="tenant-456",
                user_id="user-123",
                policy_id="nonexistent",
                updates=updates,
                logger=mock_audit_logger,
                revocation_manager=mock_revocation_manager
            )
        
        assert exc_info.value.status_code == 404


class TestDeletePolicy:
    """Tests for delete_policy function."""
    
    @pytest.mark.asyncio
    async def test_delete_policy_success(self, mock_db_connection, mock_audit_logger, mock_revocation_manager):
        """Test successfully deleting a policy."""
        mock_db_connection.execute = AsyncMock(return_value="DELETE 1")
        
        result = await delete_policy(
            db=mock_db_connection,
            tenant_id="tenant-456",
            user_id="user-123",
            policy_id="policy-to-delete",
            logger=mock_audit_logger,
            revocation_manager=mock_revocation_manager
        )
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_delete_policy_not_found(self, mock_db_connection, mock_audit_logger, mock_revocation_manager):
        """Test deleting non-existent policy raises HTTPException."""
        mock_db_connection.execute = AsyncMock(return_value="DELETE 0")
        
        with pytest.raises(HTTPException) as exc_info:
            await delete_policy(
                db=mock_db_connection,
                tenant_id="tenant-456",
                user_id="user-123",
                policy_id="nonexistent",
                logger=mock_audit_logger,
                revocation_manager=mock_revocation_manager
            )
        
        assert exc_info.value.status_code == 404


class TestAssignPolicyToUser:
    """Tests for assign_policy_to_user function."""
    
    @pytest.mark.asyncio
    async def test_assign_policy_to_user_success(self, mock_db_connection, mock_audit_logger):
        """Test successfully assigning policy to user."""
        mock_db_connection.fetchrow = AsyncMock(return_value={"id": "user-123"})
        mock_db_connection.execute = AsyncMock(return_value="INSERT 0 1")
        
        request = AssignPolicyRequest(
            user_id="user-123",
            policy_id="assigned-policy",
            resource="documents",
            actions=["read"]
        )
        
        result = await assign_policy_to_user(
            db=mock_db_connection,
            tenant_id="tenant-456",
            request=request,
            logger=mock_audit_logger
        )
        
        assert result.policy_id == "assigned-policy"
    
    @pytest.mark.asyncio
    async def test_assign_policy_user_not_found(self, mock_db_connection, mock_audit_logger):
        """Test assigning policy to non-existent user raises HTTPException."""
        mock_db_connection.fetchrow = AsyncMock(return_value=None)
        
        request = AssignPolicyRequest(
            user_id="nonexistent-user",
            policy_id="policy-1",
            resource="users",
            actions=["read"]
        )
        
        with pytest.raises(HTTPException) as exc_info:
            await assign_policy_to_user(
                db=mock_db_connection,
                tenant_id="tenant-456",
                request=request,
                logger=mock_audit_logger
            )
        
        assert exc_info.value.status_code == 404


class TestBulkAssignPolicy:
    """Tests for bulk_assign_policy function."""
    
    @pytest.mark.asyncio
    async def test_bulk_assign_policy_success(self, mock_db_connection, mock_audit_logger):
        """Test bulk assigning policy to multiple users."""
        mock_db_connection.executemany = AsyncMock()
        
        result = await bulk_assign_policy(
            db=mock_db_connection,
            tenant_id="tenant-456",
            user_ids=["user-1", "user-2", "user-3"],
            policy_id="bulk-policy",
            resource="reports",
            actions=["read"],
            conditions=None,
            logger=mock_audit_logger
        )
        
        assert result["assigned_count"] == 3
        assert result["policy_id"] == "bulk-policy"
        assert len(result["user_ids"]) == 3
    
    @pytest.mark.asyncio
    async def test_bulk_assign_policy_db_error(self, mock_db_connection, mock_audit_logger):
        """Test bulk assign handles DB errors."""
        mock_db_connection.executemany = AsyncMock(side_effect=Exception("DB Error"))
        
        with pytest.raises(HTTPException) as exc_info:
            await bulk_assign_policy(
                db=mock_db_connection,
                tenant_id="tenant-456",
                user_ids=["user-1"],
                policy_id="policy-1",
                resource="users",
                actions=["read"],
                conditions=None,
                logger=mock_audit_logger
            )
        
        assert exc_info.value.status_code == 500


class TestGetAllTenantPolicies:
    """Tests for get_all_tenant_policies function."""
    
    @pytest.mark.asyncio
    async def test_get_all_tenant_policies(self, mock_db_connection, mock_audit_logger):
        """Test getting all policies for a tenant."""
        mock_db_connection.fetchval = AsyncMock(return_value=25)
        mock_rows = [
            {
                "policy_id": "policy-1",
                "user_id": "user-1",
                "tenant_id": "tenant-456",
                "email": "user1@example.com",
                "policy": orjson.dumps({"resource": "users", "actions": ["read"]}).decode(),
                "created_at": datetime.now(timezone.utc),
                "last_modified": None
            }
        ]
        mock_db_connection.fetch = AsyncMock(return_value=mock_rows)
        
        result = await get_all_tenant_policies(
            db=mock_db_connection,
            tenant_id="tenant-456",
            logger=mock_audit_logger,
            page=1,
            page_size=20
        )
        
        assert len(result.policies) == 1
        assert result.policies[0].user_email == "user1@example.com"
        assert result.pagination.total_items == 25


class TestTenantPolicyTemplates:
    """Tests for tenant policy template functions."""
    
    @pytest.mark.asyncio
    async def test_create_tenant_policy_template(self, mock_db_connection, mock_audit_logger):
        """Test creating a tenant policy template."""
        mock_db_connection.execute = AsyncMock(return_value="INSERT 0 1")
        
        result = await create_tenant_policy_template(
            db=mock_db_connection,
            tenant_id="tenant-456",
            policy_id="admin_template",
            policies={"resource": "all", "actions": ["manage"]},
            roles=["admin"],
            logger=mock_audit_logger
        )
        
        assert result.id
        assert result.policies["resource"] == "all"
    
    @pytest.mark.asyncio
    async def test_get_tenant_policy_templates(self, mock_db_connection, mock_audit_logger):
        """Test getting tenant policy templates."""
        mock_rows = [
            {
                "id": "template-1",
                "tenant_id": "tenant-456",
                "policies": orjson.dumps({"resource": "users", "actions": ["read"]}).decode(),
                "roles": ["user"],
                "created_at": datetime.now(timezone.utc),
                "last_modified": None
            }
        ]
        mock_db_connection.fetch = AsyncMock(return_value=mock_rows)
        
        templates = await get_tenant_policy_templates(
            db=mock_db_connection,
            tenant_id="tenant-456",
            logger=mock_audit_logger
        )
        
        assert len(templates.templates) == 1
        assert templates.templates[0].id == "template-1"
        assert templates.pagination.total_items == 1
    
    @pytest.mark.asyncio
    async def test_delete_tenant_policy_template_not_found(self, mock_db_connection, mock_audit_logger):
        """Test deleting non-existent template raises HTTPException."""
        mock_db_connection.execute = AsyncMock(return_value="DELETE 0")
        
        with pytest.raises(HTTPException) as exc_info:
            await delete_tenant_policy_template(
                db=mock_db_connection,
                tenant_id="tenant-456",
                template_id="nonexistent",
                logger=mock_audit_logger
            )
        
        assert exc_info.value.status_code == 404
