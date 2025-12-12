"""
Tests for app/models/tenants.py - Tenant settings models.
"""
import pytest
from pydantic import ValidationError

from app.models.tenants import (
    MFASettings,
    TokenSettings,
    PasswordPolicy,
    SessionSettings,
    SecuritySettings,
    BrandingSettings,
    TenantSettingsUpdate
)


class TestMFASettings:
    """Tests for MFASettings model."""
    
    def test_mfa_settings_defaults(self):
        """Test MFASettings default values."""
        settings = MFASettings()
        
        assert settings.enabled is False
        assert settings.required_for_admins is False
        assert settings.methods == ["totp", "email"]
    
    def test_mfa_settings_custom(self):
        """Test MFASettings with custom values."""
        settings = MFASettings(
            enabled=True,
            required_for_admins=True,
            methods=["totp", "sms"]
        )
        
        assert settings.enabled is True
        assert settings.required_for_admins is True
        assert "sms" in settings.methods


class TestTokenSettings:
    """Tests for TokenSettings model."""
    
    def test_token_settings_defaults(self):
        """Test TokenSettings default values."""
        settings = TokenSettings()
        
        assert settings.access_token_ttl == 3600
        assert settings.refresh_token_ttl == 604800
        assert settings.id_token_ttl == 3600
    
    def test_token_settings_custom(self):
        """Test TokenSettings with custom values."""
        settings = TokenSettings(
            access_token_ttl=1800,
            refresh_token_ttl=86400,
            id_token_ttl=900
        )
        
        assert settings.access_token_ttl == 1800
    
    def test_token_settings_min_validation(self):
        """Test that access_token_ttl has minimum validation."""
        with pytest.raises(ValidationError):
            TokenSettings(access_token_ttl=100)
    
    def test_token_settings_max_validation(self):
        """Test that access_token_ttl has maximum validation."""
        with pytest.raises(ValidationError):
            TokenSettings(access_token_ttl=100000)


class TestPasswordPolicy:
    """Tests for PasswordPolicy model."""
    
    def test_password_policy_defaults(self):
        """Test PasswordPolicy default values."""
        policy = PasswordPolicy()
        
        assert policy.min_length == 8
        assert policy.require_uppercase is True
        assert policy.require_lowercase is True
        assert policy.require_numbers is True
        assert policy.require_special is False
        assert policy.max_age_days == 90
        assert policy.prevent_reuse_count == 5
    
    def test_password_policy_custom(self):
        """Test PasswordPolicy with custom values."""
        policy = PasswordPolicy(
            min_length=12,
            require_special=True,
            max_age_days=30,
            prevent_reuse_count=10
        )
        
        assert policy.min_length == 12
        assert policy.require_special is True
    
    def test_password_policy_min_length_validation(self):
        """Test min_length has lower bound."""
        with pytest.raises(ValidationError):
            PasswordPolicy(min_length=4)
    
    def test_password_policy_max_length_validation(self):
        """Test min_length has upper bound."""
        with pytest.raises(ValidationError):
            PasswordPolicy(min_length=200)


class TestSessionSettings:
    """Tests for SessionSettings model."""
    
    def test_session_settings_defaults(self):
        """Test SessionSettings default values."""
        settings = SessionSettings()
        
        assert settings.max_concurrent_sessions == 5
        assert settings.idle_timeout_minutes == 30
        assert settings.absolute_timeout_hours == 24
    
    def test_session_settings_custom(self):
        """Test SessionSettings with custom values."""
        settings = SessionSettings(
            max_concurrent_sessions=10,
            idle_timeout_minutes=60,
            absolute_timeout_hours=48
        )
        
        assert settings.max_concurrent_sessions == 10
    
    def test_session_settings_validation(self):
        """Test SessionSettings validation."""
        with pytest.raises(ValidationError):
            SessionSettings(max_concurrent_sessions=0)
        
        with pytest.raises(ValidationError):
            SessionSettings(idle_timeout_minutes=2)


class TestSecuritySettings:
    """Tests for SecuritySettings model."""
    
    def test_security_settings_defaults(self):
        """Test SecuritySettings default values."""
        settings = SecuritySettings()
        
        assert settings.lockout_threshold == 5
        assert settings.lockout_duration_minutes == 15
        assert settings.require_email_verification is True
    
    def test_security_settings_custom(self):
        """Test SecuritySettings with custom values."""
        settings = SecuritySettings(
            lockout_threshold=10,
            lockout_duration_minutes=30,
            require_email_verification=False
        )
        
        assert settings.lockout_threshold == 10
        assert settings.require_email_verification is False
    
    def test_security_settings_validation(self):
        """Test SecuritySettings validation."""
        with pytest.raises(ValidationError):
            SecuritySettings(lockout_threshold=1)


class TestBrandingSettings:
    """Tests for BrandingSettings model."""
    
    def test_branding_settings_defaults(self):
        """Test BrandingSettings default values."""
        settings = BrandingSettings()
        
        assert settings.logo_url is None
        assert settings.primary_color == "#3B82F6"
        assert settings.company_name is None
    
    def test_branding_settings_custom(self):
        """Test BrandingSettings with custom values."""
        settings = BrandingSettings(
            logo_url="https://example.com/logo.png",
            primary_color="#FF5733",
            company_name="Acme Corp"
        )
        
        assert settings.logo_url == "https://example.com/logo.png"
        assert settings.company_name == "Acme Corp"


class TestTenantSettingsUpdate:
    """Tests for TenantSettingsUpdate model."""
    
    def test_tenant_settings_update_empty(self):
        """Test TenantSettingsUpdate with no fields."""
        update = TenantSettingsUpdate()
        
        assert update.mfa is None
        assert update.tokens is None
        assert update.password_policy is None
        assert update.session is None
        assert update.security is None
        assert update.branding is None
    
    def test_tenant_settings_update_partial(self):
        """Test TenantSettingsUpdate with partial fields."""
        update = TenantSettingsUpdate(
            mfa=MFASettings(enabled=True),
            tokens=TokenSettings(access_token_ttl=1800)
        )
        
        assert update.mfa.enabled is True
        assert update.tokens.access_token_ttl == 1800
        assert update.password_policy is None
    
    def test_tenant_settings_update_all_fields(self):
        """Test TenantSettingsUpdate with all fields."""
        update = TenantSettingsUpdate(
            mfa=MFASettings(enabled=True),
            tokens=TokenSettings(),
            password_policy=PasswordPolicy(min_length=12),
            session=SessionSettings(),
            security=SecuritySettings(),
            branding=BrandingSettings(company_name="Test Corp")
        )
        
        assert update.mfa.enabled is True
        assert update.password_policy.min_length == 12
        assert update.branding.company_name == "Test Corp"
