"""
Pydantic response schemas for FastAPI OpenAPI/Swagger documentation.
These mirror the dataclass responses but are used only for response_model typing.
"""
from datetime import datetime
from typing import Optional, List, Any, Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, Field


T = TypeVar("T")


class APIResponseSchema(BaseModel, Generic[T]):
    """Generic API response wrapper for Swagger docs."""
    success: bool = True
    data: Optional[T] = None
    message: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class PaginationSchema(BaseModel):
    page: int = 1
    page_size: int = 20
    total_items: int = 0
    total_pages: int = 0


class PaginatedResponseSchema(BaseModel, Generic[T]):
    """Paginated response wrapper for Swagger docs."""
    success: bool = True
    data: List[T] = []
    pagination: PaginationSchema = Field(default_factory=PaginationSchema)
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class TokenResponseSchema(BaseModel):
    access_token: str
    token_type: str = "Bearer"


class RevokedCountResponseSchema(BaseModel):
    revoked_count: int


class RevokedResponseSchema(BaseModel):
    revoked: bool


class SessionInfoSchema(BaseModel):
    jti: str
    device_info: Optional[dict] = None
    ip_address: Optional[str] = None
    created_at: str = ""
    expires_at: str = ""


class TenantSessionInfoSchema(BaseModel):
    jti: str
    user_id: str
    user_email: str
    device_info: Optional[dict] = None
    ip_address: Optional[str] = None
    created_at: str = ""
    expires_at: str = ""
    status: str = "active"


class UserResponseSchema(BaseModel):
    id: str
    email: str
    first_name: str
    last_name: str
    full_name: str
    role: str
    is_active: bool
    created_at: Optional[str] = None
    email_verified: Optional[bool] = None
    last_login: Optional[str] = None


class UserListResponseSchema(BaseModel):
    users: List[UserResponseSchema]
    pagination: PaginationSchema


class MFASettingsSchema(BaseModel):
    enabled: bool = False
    required_for_admins: bool = False
    methods: List[str] = ["totp", "email"]


class TokenSettingsSchema(BaseModel):
    access_token_ttl: int = 3600
    refresh_token_ttl: int = 604800
    id_token_ttl: int = 3600


class PasswordPolicySchema(BaseModel):
    min_length: int = 8
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_numbers: bool = True
    require_special: bool = False
    max_age_days: int = 90
    prevent_reuse_count: int = 5


class SessionSettingsSchema(BaseModel):
    max_concurrent_sessions: int = 5
    idle_timeout_minutes: int = 30
    absolute_timeout_hours: int = 24


class SecuritySettingsSchema(BaseModel):
    lockout_threshold: int = 5
    lockout_duration_minutes: int = 15
    require_email_verification: bool = True


class BrandingSchema(BaseModel):
    logo_url: Optional[str] = None
    primary_color: str = "#3B82F6"
    company_name: Optional[str] = None


class TenantSettingsResponseSchema(BaseModel):
    mfa: dict
    tokens: dict
    password_policy: dict
    session: dict
    security: dict
    branding: dict


class TenantResponseSchema(BaseModel):
    id: str
    name: str
    domain: str
    root: Optional[str]
    settings: dict
    is_active: bool
    created_at: Optional[str] = None


class OTPProvisionResponseSchema(BaseModel):
    otp_secret: str
    uri: str
    backup_codes: List[str]
    warning: str = (
        "Save this information securely - it won't be shown again. "
        "Anyone with the secret can generate your OTP codes."
    )


class OTPVerifyResponseSchema(BaseModel):
    verified: bool


class EmailVerificationResponseSchema(BaseModel):
    message: str = "Email verified successfully. You can now log in."


class OnboardingResponseSchema(BaseModel):
    tenant_id: UUID
    user_id: UUID
    message: str = "Onboarding initiated. Check email for verification."


class PolicyResponseSchema(BaseModel):
    policy_id: str
    user_id: str
    tenant_id: str
    resource: str
    actions: List[str]
    conditions: Optional[dict] = None
    created_at: Optional[str] = None
    last_modified: Optional[str] = None


class BulkAssignResponseSchema(BaseModel):
    assigned_count: int
    user_ids: List[str]


class PolicyTemplateResponseSchema(BaseModel):
    """Policy template schema for tenant-level reusable policies."""
    policy_id: str
    tenant_id: str
    policies: dict
    roles: List[str] = []
    created_at: Optional[str] = None
    last_modified: Optional[str] = None


class TenantPoliciesPageSchema(BaseModel):
    """Paginated tenant policies response."""
    policies: List[PolicyResponseSchema]
    pagination: PaginationSchema
