from dataclasses import dataclass
from typing import Any, Optional, List
from pydantic import BaseModel, field_validator


class PolicyCreate(BaseModel):
    policy_id: str
    resource: str
    actions: List[str]
    conditions: Optional[dict[str, Any]] = None

    @field_validator('actions')
    @classmethod
    def validate_actions(cls, v):
        valid_actions = {
            'read', 'write', 'delete', 'approve', 'reject',
            'execute', 'assign', 'manage', 'export', 'import',
            'activate', 'archive'
        }
        for action in v:
            if action.lower() not in valid_actions:
                raise ValueError(f"Invalid action: {action}. Must be one of {valid_actions}")
        return [a.lower() for a in v]


class PolicyUpdate(BaseModel):
    resource: Optional[str] = None
    actions: Optional[List[str]] = None
    conditions: Optional[dict[str, Any]] = None

    @field_validator('actions')
    @classmethod
    def validate_actions(cls, v):
        if v is None:
            return v
        valid_actions = {
            'read', 'write', 'delete', 'approve', 'reject',
            'execute', 'assign', 'manage', 'export', 'import',
            'activate', 'archive'
        }
        for action in v:
            if action.lower() not in valid_actions:
                raise ValueError(f"Invalid action: {action}. Must be one of {valid_actions}")
        return [a.lower() for a in v]


@dataclass(slots=True)
class PolicyResponse:
    policy_id: str
    user_id: str
    tenant_id: str
    resource: str
    actions: List[str]
    conditions: Optional[dict[str, Any]] = None
    created_at: Optional[str] = None
    last_modified: Optional[str] = None


class AssignPolicyRequest(BaseModel):
    user_id: str
    policy_id: str
    resource: str
    actions: List[str]
    conditions: Optional[dict[str, Any]] = None

    @field_validator('actions')
    @classmethod
    def validate_actions(cls, v):
        valid_actions = {
            'read', 'write', 'delete', 'approve', 'reject',
            'execute', 'assign', 'manage', 'export', 'import',
            'activate', 'archive'
        }
        for action in v:
            if action.lower() not in valid_actions:
                raise ValueError(f"Invalid action: {action}. Must be one of {valid_actions}")
        return [a.lower() for a in v]


class BulkAssignRequest(BaseModel):
    user_ids: List[str]
    policy_id: str
    resource: str
    actions: List[str]
    conditions: Optional[dict[str, Any]] = None
