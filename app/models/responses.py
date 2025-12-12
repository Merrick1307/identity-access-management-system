"""
Response dataclasses for API endpoints.
All response models use slots=True for memory efficiency.
"""
from dataclasses import dataclass, field
from typing import Optional, List, Any


@dataclass(slots=True)
class TokenResponse:
    access_token: str
    token_type: str = "Bearer"


@dataclass(slots=True)
class RevokedCountResponse:
    revoked_count: int


@dataclass(slots=True)
class RevokedResponse:
    revoked: bool


@dataclass(slots=True)
class SessionInfo:
    jti: str
    device_info: Optional[dict] = None
    ip_address: Optional[str] = None
    created_at: str = ""
    expires_at: str = ""


@dataclass(slots=True)
class TenantSessionInfo:
    jti: str
    user_id: str
    user_email: str
    device_info: Optional[dict] = None
    ip_address: Optional[str] = None
    created_at: str = ""
    expires_at: str = ""
    status: str = "active"


@dataclass(slots=True)
class UserResponse:
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


@dataclass(slots=True)
class PaginationInfo:
    page: int
    page_size: int
    total_items: int
    total_pages: int


@dataclass(slots=True)
class UserListResponse:
    users: List[UserResponse]
    pagination: PaginationInfo


@dataclass(slots=True)
class MFASettingsResponse:
    enabled: bool = False
    required_for_admins: bool = False
    methods: List[str] = field(default_factory=lambda: ["totp", "email"])


@dataclass(slots=True)
class TokenSettingsResponse:
    access_token_ttl: int = 3600
    refresh_token_ttl: int = 604800
    id_token_ttl: int = 3600


@dataclass(slots=True)
class PasswordPolicyResponse:
    min_length: int = 8
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_numbers: bool = True
    require_special: bool = False
    max_age_days: int = 90
    prevent_reuse_count: int = 5


@dataclass(slots=True)
class SessionSettingsResponse:
    max_concurrent_sessions: int = 5
    idle_timeout_minutes: int = 30
    absolute_timeout_hours: int = 24


@dataclass(slots=True)
class SecuritySettingsResponse:
    lockout_threshold: int = 5
    lockout_duration_minutes: int = 15
    require_email_verification: bool = True


@dataclass(slots=True)
class BrandingResponse:
    logo_url: Optional[str] = None
    primary_color: str = "#3B82F6"
    company_name: Optional[str] = None


@dataclass(slots=True)
class TenantSettingsResponse:
    mfa: dict
    tokens: dict
    password_policy: dict
    session: dict
    security: dict
    branding: dict


@dataclass(slots=True)
class TenantResponse:
    id: str
    name: str
    domain: str
    root: Optional[str]
    settings: dict
    is_active: bool
    created_at: Optional[str] = None


@dataclass(slots=True)
class OTPProvisionResponse:
    otp_secret: str
    uri: str
    backup_codes: List[str]
    warning: str = (
        "Save this information securely - it won't be shown again. "
        "Anyone with the secret can generate your OTP codes."
    )


@dataclass(slots=True)
class OTPVerifyResponse:
    verified: bool


# ============== Email Verification ==============
@dataclass(slots=True)
class EmailVerificationResponse:
    message: str = "Email verified successfully. You can now log in."
