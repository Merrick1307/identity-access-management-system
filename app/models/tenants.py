from typing import List, Optional

from pydantic import BaseModel, Field


class MFASettings(BaseModel):
    enabled: bool = False
    required_for_admins: bool = False
    methods: List[str] = ["totp", "email"]


class TokenSettings(BaseModel):
    access_token_ttl: int = Field(3600, ge=300, le=86400)  # 5 min to 24 hours
    refresh_token_ttl: int = Field(604800, ge=3600, le=2592000)  # 1 hour to 30 days
    id_token_ttl: int = Field(3600, ge=300, le=86400)


class PasswordPolicy(BaseModel):
    min_length: int = Field(8, ge=6, le=128)
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_numbers: bool = True
    require_special: bool = False
    max_age_days: int = Field(90, ge=0, le=365)
    prevent_reuse_count: int = Field(5, ge=0, le=24)


class SessionSettings(BaseModel):
    max_concurrent_sessions: int = Field(5, ge=1, le=100)
    idle_timeout_minutes: int = Field(30, ge=5, le=1440)
    absolute_timeout_hours: int = Field(24, ge=1, le=168)


class SecuritySettings(BaseModel):
    lockout_threshold: int = Field(5, ge=3, le=20)
    lockout_duration_minutes: int = Field(15, ge=1, le=1440)
    require_email_verification: bool = True


class BrandingSettings(BaseModel):
    logo_url: Optional[str] = None
    primary_color: str = "#3B82F6"
    company_name: Optional[str] = None


class TenantSettingsUpdate(BaseModel):
    mfa: Optional[MFASettings] = None
    tokens: Optional[TokenSettings] = None
    password_policy: Optional[PasswordPolicy] = None
    session: Optional[SessionSettings] = None
    security: Optional[SecuritySettings] = None
    branding: Optional[BrandingSettings] = None