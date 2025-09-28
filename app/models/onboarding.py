from typing import Any, Optional, List

from pydantic import BaseModel, EmailStr, validator
from uuid import UUID

class TenantCreate(BaseModel):
    name: str
    domain: str
    root: str

class RootUserCreate(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str
    role: str  = 'root'

    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        return v



class OnboardingResponse(BaseModel):
    tenant_id: UUID
    user_id: UUID
    message: str = "Onboarding initiated. Check email for verification."

class Policy(BaseModel):
    policy_id: str
    policy: dict[str, Any]

class TenantOnboardingRequest(BaseModel):
    tenant: TenantCreate
    user: RootUserCreate
    tenant_policies: Optional[List[Policy]]