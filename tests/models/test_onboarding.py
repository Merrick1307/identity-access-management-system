"""
Tests for app/models/onboarding.py - Onboarding models.
"""
import pytest
from pydantic import ValidationError

from app.models.onboarding import (
    TenantCreate,
    RootUserCreate,
    OnboardingResponse,
    Policy,
    TenantOnboardingRequest
)


class TestTenantCreate:
    """Tests for TenantCreate model."""
    
    def test_tenant_create_valid(self):
        """Test creating a valid tenant."""
        tenant = TenantCreate(
            name="Acme Corp",
            domain="acme.com"
        )
        
        assert tenant.name == "Acme Corp"
        assert tenant.domain == "acme.com"
        assert tenant.root is None
    
    def test_tenant_create_with_root(self):
        """Test creating tenant with root email."""
        tenant = TenantCreate(
            name="Test Corp",
            domain="test.com",
            root="admin@test.com"
        )
        
        assert tenant.root == "admin@test.com"
    
    def test_tenant_create_missing_name(self):
        """Test that missing name raises ValidationError."""
        with pytest.raises(ValidationError):
            TenantCreate(domain="example.com")
    
    def test_tenant_create_missing_domain(self):
        """Test that missing domain raises ValidationError."""
        with pytest.raises(ValidationError):
            TenantCreate(name="Test Corp")


class TestRootUserCreate:
    """Tests for RootUserCreate model."""
    
    def test_root_user_create_valid(self):
        """Test creating a valid root user."""
        user = RootUserCreate(
            email="admin@example.com",
            password="securepassword123",
            first_name="Admin",
            last_name="User"
        )
        
        assert user.email == "admin@example.com"
        assert user.password == "securepassword123"
        assert user.first_name == "Admin"
        assert user.last_name == "User"
        assert user.role == "root"
    
    def test_root_user_create_custom_role(self):
        """Test creating root user with custom role."""
        user = RootUserCreate(
            email="admin@example.com",
            password="securepassword123",
            first_name="Admin",
            last_name="User",
            role="superadmin"
        )
        
        assert user.role == "superadmin"
    
    def test_root_user_create_password_too_short(self):
        """Test that short password raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            RootUserCreate(
                email="admin@example.com",
                password="short",
                first_name="Admin",
                last_name="User"
            )
        
        assert "at least 8 characters" in str(exc_info.value)
    
    def test_root_user_create_password_exactly_8_chars(self):
        """Test password with exactly 8 characters is valid."""
        user = RootUserCreate(
            email="admin@example.com",
            password="12345678",
            first_name="Admin",
            last_name="User"
        )
        
        assert len(user.password) == 8
    
    def test_root_user_create_invalid_email(self):
        """Test that invalid email raises ValidationError."""
        with pytest.raises(ValidationError):
            RootUserCreate(
                email="not-an-email",
                password="securepassword123",
                first_name="Admin",
                last_name="User"
            )
    
    def test_root_user_create_missing_fields(self):
        """Test that missing required fields raise ValidationError."""
        with pytest.raises(ValidationError):
            RootUserCreate(
                email="admin@example.com",
                password="securepassword123"
            )


class TestOnboardingResponse:
    """Tests for OnboardingResponse model."""
    
    def test_onboarding_response_creation(self):
        """Test creating onboarding response."""
        from uuid import uuid4
        
        tenant_id = uuid4()
        user_id = uuid4()
        
        response = OnboardingResponse(
            tenant_id=tenant_id,
            user_id=user_id
        )
        
        assert response.tenant_id == tenant_id
        assert response.user_id == user_id
        assert "verification" in response.message.lower()
    
    def test_onboarding_response_custom_message(self):
        """Test onboarding response with custom message."""
        from uuid import uuid4
        
        response = OnboardingResponse(
            tenant_id=uuid4(),
            user_id=uuid4(),
            message="Custom success message"
        )
        
        assert response.message == "Custom success message"


class TestPolicy:
    """Tests for Policy model."""
    
    def test_policy_creation(self):
        """Test creating a policy."""
        policy = Policy(
            policy_id="admin_access",
            policy={
                "resource": "all",
                "actions": ["manage", "write", "read"],
                "conditions": {}
            }
        )
        
        assert policy.policy_id == "admin_access"
        assert policy.policy["resource"] == "all"
        assert "manage" in policy.policy["actions"]
    
    def test_policy_with_conditions(self):
        """Test creating policy with conditions."""
        policy = Policy(
            policy_id="dept_policy",
            policy={
                "resource": "documents",
                "actions": ["read"],
                "conditions": {"department": "engineering"}
            }
        )
        
        assert policy.policy["conditions"]["department"] == "engineering"
    
    def test_policy_missing_policy_id(self):
        """Test that missing policy_id raises ValidationError."""
        with pytest.raises(ValidationError):
            Policy(policy={"resource": "users", "actions": ["read"]})
    
    def test_policy_missing_policy_dict(self):
        """Test that missing policy dict raises ValidationError."""
        with pytest.raises(ValidationError):
            Policy(policy_id="test")


class TestTenantOnboardingRequest:
    """Tests for TenantOnboardingRequest model."""
    
    def test_tenant_onboarding_request_valid(self):
        """Test creating a valid onboarding request."""
        request = TenantOnboardingRequest(
            tenant=TenantCreate(name="New Corp", domain="newcorp.com"),
            user=RootUserCreate(
                email="admin@newcorp.com",
                password="securepassword123",
                first_name="Admin",
                last_name="User"
            )
        )
        
        assert request.tenant.name == "New Corp"
        assert request.user.email == "admin@newcorp.com"
        assert request.tenant_policies is None
    
    def test_tenant_onboarding_request_with_policies(self):
        """Test onboarding request with tenant policies."""
        request = TenantOnboardingRequest(
            tenant=TenantCreate(name="Policy Corp", domain="policycorp.com"),
            user=RootUserCreate(
                email="admin@policycorp.com",
                password="securepassword123",
                first_name="Admin",
                last_name="User"
            ),
            tenant_policies=[
                Policy(
                    policy_id="viewer_policy",
                    policy={"resource": "documents", "actions": ["read"]}
                ),
                Policy(
                    policy_id="editor_policy",
                    policy={"resource": "documents", "actions": ["read", "write"]}
                )
            ]
        )
        
        assert len(request.tenant_policies) == 2
        assert request.tenant_policies[0].policy_id == "viewer_policy"
    
    def test_tenant_onboarding_request_missing_tenant(self):
        """Test that missing tenant raises ValidationError."""
        with pytest.raises(ValidationError):
            TenantOnboardingRequest(
                user=RootUserCreate(
                    email="admin@example.com",
                    password="securepassword123",
                    first_name="Admin",
                    last_name="User"
                )
            )
    
    def test_tenant_onboarding_request_missing_user(self):
        """Test that missing user raises ValidationError."""
        with pytest.raises(ValidationError):
            TenantOnboardingRequest(
                tenant=TenantCreate(name="Test", domain="test.com")
            )
