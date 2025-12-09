from typing import Optional
from pydantic import BaseModel

class TenantPolicyCreate(BaseModel):
    policy_id: str
    resource: str
    actions: list[str]
    conditions: Optional[dict] = None
    roles: Optional[list[str]] = None


class TenantPolicyUpdate(BaseModel):
    resource: Optional[str] = None
    actions: Optional[list[str]] = None
    conditions: Optional[dict] = None
    roles: Optional[list[str]] = None


class AssignTemplateRequest(BaseModel):
    template_id: str
    user_id: str
