from typing import Optional, Union

from fastapi import APIRouter, Depends, Request, BackgroundTasks

from app.audit_logs import AuditLogger, background_logger
from app.core.authz import check_permission, check_condition
from app.core.jwt_utils import verify_and_return_jwt_payload, VerifiedTokenData
from app.core.responses import APIResponse
from app.exceptions.domain import BusinessValidationError
from app.models.authz import Authorize, AuthzResponse

router: APIRouter = APIRouter()


def _principal_dict(user_object) -> dict:
    """
    (Caller already has the token; this is mainly for convenience.)
    """
    return {
        "tenant_id": getattr(user_object, "tenant_id", None),
        "user_id": getattr(user_object, "user_id", None),
        "sub": getattr(user_object, "sub", None) or getattr(user_object, "email", None),
        "role": getattr(user_object, "role", None),
        "scope": getattr(user_object, "scope", None),
        "aud": getattr(user_object, "aud", None),
        "iss": getattr(user_object, "iss", None),
        "iat": getattr(user_object, "iat", None),
        "exp": getattr(user_object, "exp", None),
        "jti": getattr(user_object, "jti", None),
        "client_id": getattr(user_object, "client_id", None),
        "grant_type": getattr(user_object, "grant_type", None),
    }

@router.post("/decide", response_model=APIResponse[Union[bool, AuthzResponse]])
async def authorize(
        request: Authorize,
        app_state: Request,
        background_tasks: BackgroundTasks,
        logger_obj: AuditLogger = Depends(background_logger),
        user_object: VerifiedTokenData = Depends(
            verify_and_return_jwt_payload
        )
) -> Union[bool, AuthzResponse]:
    include_principal = app_state.headers.get("x-include-principal", "false").lower() == "true"
    include_policy = app_state.headers.get("x-include-policy", "false").lower() == "true"  # optional

    grant_type: str = request.grant_type
    resource: str = request.resource
    check_perm_condition: bool = request.check_condition

    principal = _principal_dict(user_object) if include_principal else None
    condition_result: Optional[bool] = None

    if grant_type == "fga":
        user_policy: dict = user_object.policy
        permission_needed: str = request.action

        permitted: bool = check_permission(
            user_policy=user_policy, permission_needed=permission_needed,
            resource=resource
        )
        if permitted:
            if check_perm_condition:
                async with app_state.state.dbconnection.acquire() as dbconnection:
                    tenant_id: str = user_object.tenant_id
                    user_id: str = user_object.user_id
                    conditions: dict = request.conditions_to_check
                    condition_result = await check_condition(
                        db=dbconnection, conditions_to_compare=conditions,
                        tenant_id=tenant_id, user_id=user_id, user_policy=user_policy,
                        resource=resource
                    )
            logger_obj.audit(
                action="permission_check_result",
                user_id=user_object.user_id,
                resource=resource,
                permission=permission_needed,
                result="granted" if permitted else "denied",
                tenant_id=user_object.tenant_id,
            )
        if not permitted:
            logger_obj.warning(
                "Access denied for user",
                user_id=user_object.user_id,
                tenant_id=user_object.tenant_id,
                resource=resource,
                required_permission=permission_needed,
            )

            # legacy behavior: return bool
        if not include_principal:
            # if condition check was requested, return that boolean instead (existing behavior)
            data = condition_result if check_perm_condition and permitted else permitted
            # noinspection PyTypeChecker
            return {
                "success": True, "data": data, "message": "Decision request successful",
                "timestamp": None
            }

            # enhanced response for better compatibility: return decision + principal (+ optional extras)
        resp = {
            "allow": permitted if not check_perm_condition else (condition_result if permitted else False),
            "permitted": permitted,
            "condition_checked": bool(check_perm_condition),
            "condition_result": condition_result,
            "resource": resource,
            "action": permission_needed,
            "principal": principal,
        }
        if include_policy:
            resp["principal"]["policy"] = user_policy

        # noinspection PyTypeChecker
        return {
            "success":True, "data":resp, "message":"Decision request successful",
            "timestamp":None
        }
    raise BusinessValidationError(f"Unsupported grant type: grant_type '{grant_type}' not supported")
