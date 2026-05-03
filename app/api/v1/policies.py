from typing import List

import asyncpg
from fastapi import APIRouter, Depends, Query, Request

from app.audit_logs import AuditLogger, background_logger
from app.core.jwt_utils import verify_and_return_jwt_payload, VerifiedTokenData
from app.core.responses import (
    success_response, created_response, no_content_response, 
    not_found_response, OrjsonResponse
)
from app.core.token_revocation import TokenRevocationManager
from app.database import get_database_pool, get_revocation_manager
from app.exceptions.database_error_module import handle_database_exceptions
from app.exceptions.http_error_module import handle_http_exceptions
from app.models.policy import (
    PolicyCreate, PolicyUpdate,
    AssignPolicyRequest, BulkAssignRequest
)
from app.models.tenant_policies import TenantPolicyCreate, TenantPolicyUpdate, AssignTemplateRequest
from app.models.response_schemas import (
    APIResponseSchema, PolicyResponseSchema, BulkAssignResponseSchema,
    PolicyTemplateResponseSchema, TenantPoliciesPageSchema
)
from app.services.policy_service import (
    get_user_policies, get_policy_by_id, create_policy, update_policy,
    delete_policy, assign_policy_to_user, bulk_assign_policy,
    revoke_policy_from_user, get_all_tenant_policies,
    create_tenant_policy_template, get_tenant_policy_templates,
    get_tenant_policy_template_by_id, update_tenant_policy_template,
    delete_tenant_policy_template, assign_template_to_user
)

router: APIRouter = APIRouter()


@router.get(
    "/me",
    response_model=APIResponseSchema[List[PolicyResponseSchema]],
    summary="Get my policies",
    description="Retrieve all access policies assigned to the currently authenticated user. "
                "Returns a list of policies defining what resources and actions the user can access."
)
@handle_http_exceptions
@handle_database_exceptions
async def get_my_policies(
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    logger: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    policies = await get_user_policies(db, user.tenant_id, user.user_id, logger)
    return success_response(
        data=[p for p in policies],
        message=f"Retrieved {len(policies)} policies"
    )


@router.get(
    "/me/{policy_id}",
    response_model=APIResponseSchema[PolicyResponseSchema],
    summary="Get my specific policy",
    description="Retrieve a specific policy by ID assigned to the currently authenticated user. "
                "Returns detailed policy information including resource, actions, and conditions."
)
@handle_http_exceptions
@handle_database_exceptions
async def get_my_policy_by_id(
    policy_id: str,
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    logger: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    policy = await get_policy_by_id(db, user.tenant_id, user.user_id, policy_id, logger)
    if not policy:
        return not_found_response(resource=f"Policy '{policy_id}'")
    return success_response(data=policy)


@router.get(
    "/user/{user_id}",
    response_model=APIResponseSchema[List[PolicyResponseSchema]],
    summary="Get user policies (Admin)",
    description="Retrieve all access policies assigned to a specific user within the tenant. "
                "Requires admin privileges. Used for auditing and managing user permissions."
)
@handle_http_exceptions
@handle_database_exceptions
async def get_user_policies_by_id(
    user_id: str,
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    logger: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    policies = await get_user_policies(db, user.tenant_id, user_id, logger)
    return success_response(
        data=[p for p in policies],
        message=f"Retrieved {len(policies)} policies for user"
    )


@router.get(
    "/user/{user_id}/{policy_id}",
    response_model=APIResponseSchema[PolicyResponseSchema],
    summary="Get specific user policy (Admin)",
    description="Retrieve a specific policy by ID for a given user. "
                "Requires admin privileges. Returns full policy details including conditions."
)
@handle_http_exceptions
@handle_database_exceptions
async def get_specific_user_policy(
    user_id: str,
    policy_id: str,
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    logger: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    policy = await get_policy_by_id(db, user.tenant_id, user_id, policy_id, logger)
    if not policy:
        return not_found_response(resource=f"Policy '{policy_id}' for user '{user_id}'")
    return success_response(data=policy)


@router.post(
    "/user/{user_id}",
    response_model=APIResponseSchema[PolicyResponseSchema],
    summary="Create user policy (Admin)",
    description="Create a new access policy for a specific user. "
                "Defines resource access, allowed actions, and optional conditions. "
                "Requires admin privileges."
)
@handle_http_exceptions
@handle_database_exceptions
async def create_user_policy(
    user_id: str,
    policy: PolicyCreate,
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    logger: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    created = await create_policy(db, user.tenant_id, user_id, policy, logger)
    return created_response(
        data=created,
        message=f"Policy '{policy.policy_id}' created successfully"
    )


@router.put(
    "/user/{user_id}/{policy_id}",
    response_model=APIResponseSchema[PolicyResponseSchema],
    summary="Update user policy (Admin)",
    description="Update an existing policy for a user. "
                "Supports partial updates - only provided fields will be modified. "
                "Requires admin privileges."
)
@handle_http_exceptions
@handle_database_exceptions
async def update_user_policy(
    user_id: str,
    policy_id: str,
    updates: PolicyUpdate,
    revocation_manager: TokenRevocationManager = Depends(get_revocation_manager),
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    logger: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    updated = await update_policy(
        db, user.tenant_id, user_id,
        policy_id, updates, logger,
        revocation_manager
    )
    return success_response(
        data=updated,
        message=f"Policy '{policy_id}' updated successfully"
    )


@router.delete(
    "/user/{user_id}/{policy_id}",
    status_code=204,
    summary="Delete user policy (Admin)",
    description="Permanently delete a policy from a user. "
                "This action cannot be undone. Requires admin privileges."
)
@handle_http_exceptions
@handle_database_exceptions
async def delete_user_policy(
    user_id: str,
    policy_id: str,
    revocation_manager: TokenRevocationManager = Depends(get_revocation_manager),
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    logger: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    await delete_policy(
        db, user.tenant_id, user_id, policy_id,
        logger, revocation_manager
    )
    return no_content_response()


@router.post(
    "/assign",
    response_model=APIResponseSchema[PolicyResponseSchema],
    summary="Assign policy to user (Admin)",
    description="Assign an existing or new policy to a specific user. "
                "Creates the policy-user association with specified resource, actions, and conditions. "
                "Requires admin privileges."
)
@handle_http_exceptions
@handle_database_exceptions
async def assign_policy(
    request: AssignPolicyRequest,
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    logger: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    result = await assign_policy_to_user(db, user.tenant_id, request, logger)
    return created_response(
        data=result,
        message=f"Policy assigned to user '{request.user_id}'"
    )


@router.post(
    "/bulk-assign",
    response_model=APIResponseSchema[BulkAssignResponseSchema],
    summary="Bulk assign policy to multiple users (Admin)",
    description="Assign the same policy to multiple users at once. "
                "Efficient for applying role-based or group permissions. "
                "Returns count of successfully assigned policies. Requires admin privileges."
)
@handle_http_exceptions
@handle_database_exceptions
async def bulk_assign_policies(
    request: BulkAssignRequest,
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    logger: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    result = await bulk_assign_policy(
        db, user.tenant_id, request.user_ids, request.policy_id,
        request.resource, request.actions, request.conditions, logger
    )
    return created_response(
        data=result,
        message=f"Policy assigned to {result['assigned_count']} users"
    )


@router.delete(
    "/revoke/{user_id}/{policy_id}",
    response_model=APIResponseSchema[None],
    summary="Revoke policy from user (Admin)",
    description="Remove a specific policy from a user, revoking their access. "
                "The policy definition remains in the system but the user loses access. "
                "Requires admin privileges."
)
@handle_http_exceptions
@handle_database_exceptions
async def revoke_policy(
    user_id: str,
    policy_id: str,
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    revocation_manager: TokenRevocationManager = Depends(get_revocation_manager),
    logger: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    await revoke_policy_from_user(db, user.tenant_id, user_id, policy_id, revocation_manager, logger)
    return success_response(message=f"Policy '{policy_id}' revoked from user '{user_id}'")


@router.get(
    "/tenant",
    response_model=APIResponseSchema[TenantPoliciesPageSchema],
    summary="List all tenant policies (Admin)",
    description="Retrieve a paginated list of all policies across all users in the tenant. "
                "Used for compliance auditing and policy management. "
                "Supports pagination with page and page_size parameters. Requires admin privileges."
)
@handle_http_exceptions
@handle_database_exceptions
async def list_all_tenant_policies(
    page: int = Query(1, ge=1, description="Page number starting from 1"),
    page_size: int = Query(20, ge=1, le=100, description="Number of items per page (max 100)"),
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    logger: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    result = await get_all_tenant_policies(db, user.tenant_id, logger, page, page_size)

    return success_response(
        data=result['data'],
        message=f"Page {page} of {result['pagination']['total_pages']}"
    )


@router.get(
    "/templates",
    response_model=APIResponseSchema[List[PolicyTemplateResponseSchema]],
    summary="List policy templates (Admin)",
    description="Retrieve all reusable policy templates defined for the tenant. "
                "Templates are pre-configured policies that can be quickly assigned to users. "
                "Useful for role-based access control patterns. Requires admin privileges."
)
@handle_http_exceptions
@handle_database_exceptions
async def list_policy_templates(
    request: Request,
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    logger: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    templates = await get_tenant_policy_templates(db, user.tenant_id, logger, redis_conn=request.app.state.redis)
    return success_response(
        data=templates,
        message=f"Found {len(templates)} policy templates"
    )


@router.get(
    "/templates/{template_id}",
    response_model=APIResponseSchema[PolicyTemplateResponseSchema],
    summary="Get policy template by ID (Admin)",
    description="Retrieve a specific policy template by its ID. "
                "Returns the template definition including resource, actions, conditions, and applicable roles. "
                "Requires admin privileges."
)
@handle_http_exceptions
@handle_database_exceptions
async def get_policy_template(
    template_id: str,
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    logger: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    template = await get_tenant_policy_template_by_id(db, user.tenant_id, template_id, logger)
    if not template:
        return not_found_response(resource=f"Policy template '{template_id}'")
    return success_response(data=template)


@router.post(
    "/templates",
    response_model=APIResponseSchema[PolicyTemplateResponseSchema],
    summary="Create policy template (Admin)",
    description="Create a new reusable policy template for the tenant. "
                "Templates define standard access patterns (resource, actions, conditions) "
                "that can be assigned to multiple users. Optionally specify applicable roles. "
                "Requires admin privileges."
)
@handle_http_exceptions
@handle_database_exceptions
async def create_policy_template(
    data: TenantPolicyCreate,
    request: Request,
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    logger: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    policies = {
        "policy_id": data.policy_id,
        "resource": data.resource,
        "actions": data.actions,
        "conditions": data.conditions or {}
    }
    result = await create_tenant_policy_template(
        db, user.tenant_id, data.policy_id, policies, data.roles or [], logger,
        redis_conn=request.app.state.redis
    )
    return created_response(
        data=result,
        message=f"Policy template '{data.policy_id}' created"
    )


@router.put(
    "/templates/{template_id}",
    response_model=APIResponseSchema[PolicyTemplateResponseSchema],
    summary="Update policy template (Admin)",
    description="Update an existing policy template. "
                "Supports partial updates - only provided fields will be modified. "
                "Changes do not automatically propagate to users who already have the template assigned. "
                "Requires admin privileges."
)
@handle_http_exceptions
@handle_database_exceptions
async def update_policy_template(
    template_id: str,
    request: Request,
    data: TenantPolicyUpdate,
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    logger: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    policies = None
    if data.resource is not None or data.actions is not None or data.conditions is not None:
        # Get existing template to merge
        existing = await get_tenant_policy_template_by_id(db, user.tenant_id, template_id, logger)
        if existing:
            policies = existing['policies'].copy()
            if data.resource is not None:
                policies['resource'] = data.resource
            if data.actions is not None:
                policies['actions'] = data.actions
            if data.conditions is not None:
                policies['conditions'] = data.conditions
    
    result = await update_tenant_policy_template(
        db, user.tenant_id, template_id, policies, data.roles, logger,
        redis_conn=request.app.state.redis
    )
    return success_response(
        data=result,
        message=f"Policy template updated"
    )


@router.delete(
    "/templates/{template_id}",
    status_code=204,
    summary="Delete policy template (Admin)",
    description="Permanently delete a policy template. "
                "Existing user assignments based on this template are NOT affected. "
                "This action cannot be undone. Requires admin privileges."
)
@handle_http_exceptions
@handle_database_exceptions
async def delete_policy_template(
    template_id: str,
    request: Request,
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    logger: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    await delete_tenant_policy_template(db, user.tenant_id, template_id, logger, redis_conn=request.app.state.redis)
    return no_content_response()


@router.post(
    "/templates/assign",
    response_model=APIResponseSchema[PolicyResponseSchema],
    summary="Assign template to user (Admin)",
    description="Assign a policy template to a specific user, creating a new policy based on the template. "
                "The user receives the permissions defined in the template. "
                "Future template changes do not affect this assignment. Requires admin privileges."
)
@handle_http_exceptions
@handle_database_exceptions
async def assign_policy_template_to_user(
    data: AssignTemplateRequest,
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    logger: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    result = await assign_template_to_user(
        db, user.tenant_id, data.template_id, data.user_id, logger
    )
    return created_response(
        data=result,
        message=f"Template assigned to user '{data.user_id}'"
    )
