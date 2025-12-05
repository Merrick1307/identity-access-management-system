from typing import List

import asyncpg
from fastapi import APIRouter, Depends, Query

from app.audit_logs import AuditLogger, background_logger
from app.core.jwt_utils import verify_and_return_jwt_payload, VerifiedTokenData
from app.core.responses import (
    success_response, created_response, no_content_response, 
    not_found_response, OrjsonResponse
)
from app.database import get_database_pool
from app.exceptions.database_error_module import handle_database_exceptions
from app.exceptions.http_error_module import handle_http_exceptions
from app.models.policy import (
    PolicyCreate, PolicyUpdate, PolicyResponse, 
    AssignPolicyRequest, BulkAssignRequest
)
from app.services.policy_service import (
    get_user_policies, get_policy_by_id, create_policy, update_policy,
    delete_policy, assign_policy_to_user, bulk_assign_policy,
    revoke_policy_from_user, get_all_tenant_policies
)

router: APIRouter = APIRouter()


@router.get("/me")
@handle_http_exceptions
@handle_database_exceptions
async def get_my_policies(
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    logger: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    policies = await get_user_policies(db, user.tenant_id, user.user_id, logger)
    return success_response(
        data=[p.model_dump() for p in policies],
        message=f"Retrieved {len(policies)} policies"
    )


@router.get("/me/{policy_id}")
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
    return success_response(data=policy.model_dump())


@router.get("/user/{user_id}")
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
        data=[p.model_dump() for p in policies],
        message=f"Retrieved {len(policies)} policies for user"
    )


@router.get("/user/{user_id}/{policy_id}")
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
    return success_response(data=policy.model_dump())


@router.post("/user/{user_id}")
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
        data=created.model_dump(),
        message=f"Policy '{policy.policy_id}' created successfully"
    )


@router.put("/user/{user_id}/{policy_id}")
@handle_http_exceptions
@handle_database_exceptions
async def update_user_policy(
    user_id: str,
    policy_id: str,
    updates: PolicyUpdate,
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    logger: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    updated = await update_policy(db, user.tenant_id, user_id, policy_id, updates, logger)
    return success_response(
        data=updated.model_dump(),
        message=f"Policy '{policy_id}' updated successfully"
    )


@router.delete("/user/{user_id}/{policy_id}")
@handle_http_exceptions
@handle_database_exceptions
async def delete_user_policy(
    user_id: str,
    policy_id: str,
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    logger: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    await delete_policy(db, user.tenant_id, user_id, policy_id, logger)
    return no_content_response()


@router.post("/assign")
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
        data=result.model_dump(),
        message=f"Policy assigned to user '{request.user_id}'"
    )


@router.post("/bulk-assign")
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


@router.delete("/revoke/{user_id}/{policy_id}")
@handle_http_exceptions
@handle_database_exceptions
async def revoke_policy(
    user_id: str,
    policy_id: str,
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    logger: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    await revoke_policy_from_user(db, user.tenant_id, user_id, policy_id, logger)
    return success_response(message=f"Policy '{policy_id}' revoked from user '{user_id}'")


@router.get("/tenant")
@handle_http_exceptions
@handle_database_exceptions
async def list_all_tenant_policies(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    logger: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    result = await get_all_tenant_policies(db, user.tenant_id, logger, page, page_size)
    return success_response(
        data=result['data'],
        message=f"Page {page} of {result['pagination']['total_pages']}"
    )
