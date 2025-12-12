from typing import List

import asyncpg
from fastapi import APIRouter, Request, Depends, BackgroundTasks, HTTPException, status
from pydantic import EmailStr

from app.audit_logs import AuditLogger, background_logger
from app.core.auth import authenticate, get_client_ip, logout, refresh
from app.core.jwt_utils import verify_and_return_jwt_payload, VerifiedTokenData
from app.core.token_revocation import TokenRevocationManager
from app.services.session_service import (
    get_active_sessions, revoke_all_sessions, revoke_session,
    get_all_tenant_sessions, admin_bulk_revoke_sessions
)
from app.core.responses import success_response, no_content_response, OrjsonResponse
from app.database import get_database_pool, get_revocation_manager
from app.exceptions.database_error_module import handle_database_exceptions
from app.exceptions.http_error_module import handle_http_exceptions
from app.models.auth import Authentication, BulkRevokeRequest
from app.models.responses import TokenResponse, RevokedCountResponse, RevokedResponse
from app.models.response_schemas import (
    APIResponseSchema, TokenResponseSchema, RevokedCountResponseSchema,
    RevokedResponseSchema, SessionInfoSchema, TenantSessionInfoSchema
)

router: APIRouter = APIRouter()


@router.post(
    "/token",
    response_model=APIResponseSchema[TokenResponseSchema],
    summary="Authenticate and get access token",
    description="Authenticate a user with email and password. Returns a JWT access token "
                "for subsequent API requests. Requires X-TENANT-ID header to identify the tenant."
)
@handle_database_exceptions
async def get_token(
        request: Request,
        auth: Authentication,
        background_tasks: BackgroundTasks,
        logger_obj: AuditLogger = Depends(background_logger),
        db: asyncpg.Connection = Depends(get_database_pool)
):
    email: EmailStr = auth.email
    tenant_id: str = request.headers.get("X-TENANT-ID")
    password: str = auth.password
    email_string = str(email)
    ip = get_client_ip(request=request)

    user_agent = request.headers.get("User-Agent", "unknown")
    device_info = {"user_agent": user_agent}
    
    access_token = await authenticate(
        db=db, ip=ip, email=email_string, tenant_id=tenant_id,
        password=password, logger_obj=logger_obj, device_info=device_info
    )

    return success_response(
        data= TokenResponse(access_token=access_token),
        message="Authentication successful"
    )


@router.post(
    "/logout",
    response_model=APIResponseSchema[None],
    summary="Logout current session",
    description="Invalidate the current session token. The token will be added to the "
                "revocation list and cannot be used for further requests."
)
@handle_http_exceptions
async def logout_session(
        request: Request,
        logger_obj: AuditLogger = Depends(background_logger),
        revocation_manager: TokenRevocationManager = Depends(get_revocation_manager),
        db: asyncpg.Connection = Depends(get_database_pool)
):
    return await logout(request=request, logger=logger_obj, revocation_manager=revocation_manager, db=db)


@router.get(
    "/refresh",
    response_model=APIResponseSchema[TokenResponseSchema],
    summary="Refresh access token",
    description="Generate a new access token using the current valid token. "
                "Use this to extend session lifetime without re-authenticating."
)
@handle_http_exceptions
async def refresh_session(
        request: Request,
        logger_obj: AuditLogger = Depends(background_logger),
        revocation_manager: TokenRevocationManager = Depends(get_revocation_manager),
        db_pool: asyncpg.Connection = Depends(get_database_pool)
) -> OrjsonResponse:
    return await refresh(
        request=request,
        logger=logger_obj,
        revocation_manager=revocation_manager,
        db_pool=db_pool
    )


@router.get(
    "/sessions",
    response_model=APIResponseSchema[List[SessionInfoSchema]],
    summary="List my active sessions",
    description="Retrieve all active sessions for the current user. "
                "Shows device info, IP address, and expiration time for each session."
)
@handle_http_exceptions
@handle_database_exceptions
async def list_my_sessions(
        user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
        db: asyncpg.Connection = Depends(get_database_pool)
) -> OrjsonResponse:
    sessions = await get_active_sessions(db, user.user_id, user.tenant_id)
    return success_response(
        data=[s for s in sessions],
        message=f"Found {len(sessions)} active sessions"
    )


@router.post(
    "/logout-all",
    response_model=APIResponseSchema[RevokedCountResponseSchema],
    summary="Logout from all sessions",
    description="Revoke all active sessions for the current user, including the current session. "
                "User will need to re-authenticate on all devices."
)
@handle_http_exceptions
@handle_database_exceptions
async def logout_all_sessions(
        request: Request,
        user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
        db: asyncpg.Connection = Depends(get_database_pool),
        revocation_manager: TokenRevocationManager = Depends(get_revocation_manager),
        logger_obj: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    # To keep current session: extract JTI from token header
    current_jti = request.headers.get("Authorization", "").split(" ")[-1]
    current_jti = None  # Set to None to revoke ALL including current

    count = await revoke_all_sessions(
        db, revocation_manager, user.user_id, user.tenant_id, logger_obj, 
        reason="bulk_logout", exclude_jti=current_jti
    )
    return success_response(
        data=RevokedCountResponse(revoked_count=count),
        message=f"Revoked {count} sessions"
    )


@router.post(
    "/logout-others",
    response_model=APIResponseSchema[RevokedCountResponseSchema],
    summary="Logout other sessions",
    description="Revoke all active sessions except the current one. "
                "Useful when user suspects unauthorized access from other devices."
)
@handle_http_exceptions
@handle_database_exceptions
async def logout_other_sessions(
        request: Request,
        user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
        db: asyncpg.Connection = Depends(get_database_pool),
        revocation_manager: TokenRevocationManager = Depends(get_revocation_manager),
        logger_obj: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    import jwt
    token = request.headers.get("Authorization", "").split(" ")[-1]
    current_jti = jwt.get_unverified_header(token).get("jti")
    
    count = await revoke_all_sessions(
        db, revocation_manager, user.user_id, user.tenant_id, logger_obj,
        reason="logout_others", exclude_jti=current_jti
    )
    return success_response(
        data=RevokedCountResponse(revoked_count=count),
        message=f"Revoked {count} other sessions"
    )


@router.delete(
    "/sessions/{jti}",
    response_model=APIResponseSchema[RevokedResponseSchema],
    summary="Revoke specific session",
    description="Revoke a specific session by its JTI (JWT ID). "
                "Use the sessions list endpoint to find session JTIs."
)
@handle_http_exceptions
@handle_database_exceptions
async def revoke_specific_session(
        jti: str,
        user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
        db: asyncpg.Connection = Depends(get_database_pool),
        revocation_manager: TokenRevocationManager = Depends(get_revocation_manager)
) -> OrjsonResponse:
    revoked = await revoke_session(db, revocation_manager, jti, user.user_id, user.tenant_id, "manual_revoke")
    if revoked:
        return no_content_response()
    return success_response(data=RevokedResponse(revoked=False), message="Session not found or already revoked")


@router.get(
    "/sessions/all",
    response_model=APIResponseSchema[List[TenantSessionInfoSchema]],
    summary="List all tenant sessions (Admin)",
    description="Retrieve all active sessions across all users in the tenant. "
                "Requires admin privileges. Useful for security monitoring and compliance."
)
@handle_http_exceptions
@handle_database_exceptions
async def list_all_tenant_sessions(
        user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
        db: asyncpg.Connection = Depends(get_database_pool)
) -> OrjsonResponse:
    if user.role not in ("admin", "superadmin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    sessions = await get_all_tenant_sessions(db, user.tenant_id)
    return success_response(
        data=[s for s in sessions],
        message=f"Found {len(sessions)} active sessions"
    )


@router.get(
    "/sessions/user/{user_id}",
    response_model=APIResponseSchema[List[SessionInfoSchema]],
    summary="List user sessions (Admin)",
    description="Retrieve all active sessions for a specific user. "
                "Requires admin privileges. Use for investigating user activity."
)
@handle_http_exceptions
@handle_database_exceptions
async def list_user_sessions(
        user_id: str,
        user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
        db: asyncpg.Connection = Depends(get_database_pool)
) -> OrjsonResponse:
    if user.role not in ("admin", "superadmin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    sessions = await get_active_sessions(db, user_id, user.tenant_id)
    return success_response(
        data=[s for s in sessions],
        message=f"Found {len(sessions)} active sessions for user"
    )


@router.post(
    "/sessions/bulk-revoke",
    response_model=APIResponseSchema[RevokedCountResponseSchema],
    summary="Bulk revoke sessions (Admin)",
    description="Revoke multiple sessions by their JTIs in a single request. "
                "Requires admin privileges. Efficient for mass session invalidation."
)
@handle_http_exceptions
@handle_database_exceptions
async def admin_bulk_revoke(
        request_data: BulkRevokeRequest,
        user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
        db: asyncpg.Connection = Depends(get_database_pool),
        revocation_manager: TokenRevocationManager = Depends(get_revocation_manager),
        logger_obj: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    if user.role not in ("admin", "superadmin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    count = await admin_bulk_revoke_sessions(
        db, revocation_manager, request_data.jtis, user.tenant_id, logger_obj
    )
    return success_response(
        data=RevokedCountResponse(revoked_count=count),
        message=f"Revoked {count} sessions"
    )


@router.post(
    "/sessions/user/{user_id}/revoke-all",
    response_model=APIResponseSchema[RevokedCountResponseSchema],
    summary="Revoke all user sessions (Admin)",
    description="Force logout a specific user from all devices by revoking all their sessions. "
                "Requires admin privileges. Use for security incidents or user offboarding."
)
@handle_http_exceptions
@handle_database_exceptions
async def admin_revoke_user_sessions(
        user_id: str,
        user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
        db: asyncpg.Connection = Depends(get_database_pool),
        revocation_manager: TokenRevocationManager = Depends(get_revocation_manager),
        logger_obj: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    if user.role not in ("admin", "superadmin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    count = await revoke_all_sessions(
        db, revocation_manager, user_id, user.tenant_id, logger_obj, reason="admin_revoke"
    )
    return success_response(
        data=RevokedCountResponse(revoked_count=count),
        message=f"Revoked {count} sessions for user"
    )
