import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status

from app.audit_logs import AuditLogger, background_logger
from app.core.authz import check_permission, check_condition
from app.core.jwt_utils import verify_and_return_jwt_payload, VerifiedTokenData
from app.database import get_database_pool
from app.exceptions.database_error_module import handle_database_exceptions
from app.exceptions.http_error_module import handle_http_exceptions
from app.models.authz import Authorize

router: APIRouter = APIRouter()


@router.post("/authorize")
@handle_http_exceptions
@handle_database_exceptions
async def authorize(
        request: Authorize,
        # logger_obj: AuditLogger = Depends(background_logger),
        # dbconnection: asyncpg.Connection = Depends(
        #     get_database_pool
        # ),
        user_object: VerifiedTokenData = Depends(
            verify_and_return_jwt_payload
        )
):
    grant_type: str = request.grant_type
    resource: str = request.resource
    check_perm_condition: bool = request.check_condition
    if grant_type == "fga":
        user_policy: dict = user_object.policy
        permission_needed: str = request.action

        permitted: bool = check_permission(
            user_policy=user_policy, permission_needed=permission_needed,
            resource=resource
        )
        if permitted:
            # if check_perm_condition:
            #     tenant_id: str = user_object.tenant_id
            #     user_id: str = user_object.user_id
            #     conditions: dict = request.conditions_to_check
            #     return await check_condition(
            #         db=dbconnection, conditions_to_compare=conditions,
            #         tenant_id=tenant_id, user_id=user_id, user_policy=user_policy,
            #         resource=resource
            #     )
            # logger_obj.audit(
            #     action="permission_check_result",
            #     user_id=user_object.user_id,
            #     resource=resource,
            #     permission=permission_needed,
            #     result="granted" if permitted else "denied"
            # )
            return True
        # logger_obj.warning(
        #     "Access denied for user",
        #     user_id=user_object.user_id,
        #     tenant_id=user_object.tenant_id,
        #     resource=resource,
        #     required_permission=permission_needed
        # )
        return False