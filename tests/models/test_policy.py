"""
Tests for app/models/policy.py - Policy models.
"""
import pytest
from pydantic import ValidationError

from app.models.policy import (
    PolicyCreate,
    PolicyUpdate,
    PolicyResponse,
    AssignPolicyRequest,
    BulkAssignRequest
)


class TestPolicyCreate:
    """Tests for PolicyCreate model."""
    
    def test_policy_create_valid(self):
        """Test creating a valid policy."""
        policy = PolicyCreate(
            policy_id="admin_policy",
            resource="users",
            actions=["read", "write", "delete"]
        )
        
        assert policy.policy_id == "admin_policy"
        assert policy.resource == "users"
        assert policy.actions == ["read", "write", "delete"]
        assert policy.conditions is None
    
    def test_policy_create_with_conditions(self):
        """Test creating policy with conditions."""
        policy = PolicyCreate(
            policy_id="dept_policy",
            resource="documents",
            actions=["read"],
            conditions={"department": "engineering"}
        )
        
        assert policy.conditions == {"department": "engineering"}
    
    def test_policy_create_normalizes_actions_to_lowercase(self):
        """Test that actions are normalized to lowercase."""
        policy = PolicyCreate(
            policy_id="test_policy",
            resource="users",
            actions=["READ", "Write", "DELETE"]
        )
        
        assert policy.actions == ["read", "write", "delete"]
    
    def test_policy_create_invalid_action(self):
        """Test that invalid action raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            PolicyCreate(
                policy_id="test_policy",
                resource="users",
                actions=["read", "invalid_action"]
            )
        
        assert "Invalid action" in str(exc_info.value)
    
    def test_policy_create_all_valid_actions(self):
        """Test creating policy with all valid actions."""
        valid_actions = [
            'read', 'write', 'delete', 'approve', 'reject',
            'execute', 'assign', 'manage', 'export', 'import',
            'activate', 'archive'
        ]
        
        policy = PolicyCreate(
            policy_id="full_access",
            resource="all",
            actions=valid_actions
        )
        
        assert len(policy.actions) == 12
    
    def test_policy_create_empty_actions(self):
        """Test creating policy with empty actions list."""
        policy = PolicyCreate(
            policy_id="no_access",
            resource="users",
            actions=[]
        )
        
        assert policy.actions == []


class TestPolicyUpdate:
    """Tests for PolicyUpdate model."""
    
    def test_policy_update_partial(self):
        """Test partial policy update."""
        update = PolicyUpdate(
            actions=["read", "write"]
        )
        
        assert update.resource is None
        assert update.actions == ["read", "write"]
        assert update.conditions is None
    
    def test_policy_update_resource_only(self):
        """Test updating only resource."""
        update = PolicyUpdate(resource="new_resource")
        
        assert update.resource == "new_resource"
        assert update.actions is None
    
    def test_policy_update_all_fields(self):
        """Test updating all fields."""
        update = PolicyUpdate(
            resource="documents",
            actions=["read", "export"],
            conditions={"level": "confidential"}
        )
        
        assert update.resource == "documents"
        assert update.actions == ["read", "export"]
        assert update.conditions == {"level": "confidential"}
    
    def test_policy_update_normalizes_actions(self):
        """Test that update normalizes actions to lowercase."""
        update = PolicyUpdate(actions=["READ", "WRITE"])
        
        assert update.actions == ["read", "write"]
    
    def test_policy_update_invalid_action(self):
        """Test that invalid action in update raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            PolicyUpdate(actions=["read", "invalid"])
        
        assert "Invalid action" in str(exc_info.value)
    
    def test_policy_update_none_actions_allowed(self):
        """Test that None actions are allowed in update."""
        update = PolicyUpdate(actions=None)
        
        assert update.actions is None


class TestPolicyResponse:
    """Tests for PolicyResponse model."""
    
    def test_policy_response_creation(self):
        """Test creating a policy response."""
        response = PolicyResponse(
            policy_id="admin_policy",
            user_id="user-123",
            tenant_id="tenant-456",
            resource="users",
            actions=["read", "write"]
        )
        
        assert response.policy_id == "admin_policy"
        assert response.user_id == "user-123"
        assert response.tenant_id == "tenant-456"
    
    def test_policy_response_with_timestamps(self):
        """Test policy response with timestamps."""
        response = PolicyResponse(
            policy_id="test_policy",
            user_id="user-123",
            tenant_id="tenant-456",
            resource="documents",
            actions=["read"],
            created_at="2024-01-15T10:30:00Z",
            last_modified="2024-01-16T14:00:00Z"
        )
        
        assert response.created_at == "2024-01-15T10:30:00Z"
        assert response.last_modified == "2024-01-16T14:00:00Z"
    
    def test_policy_response_optional_fields(self):
        """Test policy response with optional fields as None."""
        response = PolicyResponse(
            policy_id="test_policy",
            user_id="user-123",
            tenant_id="tenant-456",
            resource="users",
            actions=["read"]
        )
        
        assert response.conditions is None
        assert response.created_at is None
        assert response.last_modified is None


class TestAssignPolicyRequest:
    """Tests for AssignPolicyRequest model."""
    
    def test_assign_policy_request_valid(self):
        """Test valid assign policy request."""
        request = AssignPolicyRequest(
            user_id="user-123",
            policy_id="editor_policy",
            resource="documents",
            actions=["read", "write"]
        )
        
        assert request.user_id == "user-123"
        assert request.policy_id == "editor_policy"
    
    def test_assign_policy_request_with_conditions(self):
        """Test assign policy request with conditions."""
        request = AssignPolicyRequest(
            user_id="user-123",
            policy_id="conditional_policy",
            resource="reports",
            actions=["read", "export"],
            conditions={"department": "finance"}
        )
        
        assert request.conditions == {"department": "finance"}
    
    def test_assign_policy_request_normalizes_actions(self):
        """Test that assign request normalizes actions."""
        request = AssignPolicyRequest(
            user_id="user-123",
            policy_id="test",
            resource="users",
            actions=["READ", "WRITE"]
        )
        
        assert request.actions == ["read", "write"]
    
    def test_assign_policy_request_invalid_action(self):
        """Test that invalid action raises ValidationError."""
        with pytest.raises(ValidationError):
            AssignPolicyRequest(
                user_id="user-123",
                policy_id="test",
                resource="users",
                actions=["read", "superpower"]
            )


class TestBulkAssignRequest:
    """Tests for BulkAssignRequest model."""
    
    def test_bulk_assign_request_valid(self):
        """Test valid bulk assign request."""
        request = BulkAssignRequest(
            user_ids=["user-1", "user-2", "user-3"],
            policy_id="viewer_policy",
            resource="reports",
            actions=["read"]
        )
        
        assert len(request.user_ids) == 3
        assert request.policy_id == "viewer_policy"
    
    def test_bulk_assign_request_single_user(self):
        """Test bulk assign with single user."""
        request = BulkAssignRequest(
            user_ids=["user-1"],
            policy_id="admin_policy",
            resource="users",
            actions=["manage"]
        )
        
        assert len(request.user_ids) == 1
    
    def test_bulk_assign_request_with_conditions(self):
        """Test bulk assign with conditions."""
        request = BulkAssignRequest(
            user_ids=["user-1", "user-2"],
            policy_id="dept_policy",
            resource="documents",
            actions=["read", "write"],
            conditions={"department": "engineering"}
        )
        
        assert request.conditions == {"department": "engineering"}
    
    def test_bulk_assign_request_empty_user_ids(self):
        """Test bulk assign with empty user_ids list."""
        request = BulkAssignRequest(
            user_ids=[],
            policy_id="test",
            resource="users",
            actions=["read"]
        )
        
        assert request.user_ids == []
