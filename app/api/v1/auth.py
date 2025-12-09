from typing import List
import asyncpg
from fastapi import APIRouter, Request, Depends, BackgroundTasks, HTTPException, status
from pydantic import BaseModel, EmailStr

from app.audit_logs import AuditLogger, background_logger
from app.core.auth import authenticate, get_client_ip, logout, refresh
from app.core.jwt_utils import verify_and_return_jwt_payload, VerifiedTokenData
from app.core.token_revocation import TokenRevocationManager
from app.services.session_service import (
    get_active_sessions, revoke_all_sessions, revoke_session,
    get_all_tenant_sessions, admin_revoke_session, admin_bulk_revoke_sessions
)
from app.core.responses import success_response, no_content_response, OrjsonResponse
from app.database import get_database_pool, get_revocation_manager
from app.exceptions.database_error_module import handle_database_exceptions
from app.exceptions.http_error_module import handle_http_exceptions
from app.models.auth import Authentication, BulkRevokeRequest

router: APIRouter = APIRouter()


@router.post("/token")
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
        data={"access_token": access_token, "token_type": "Bearer"},
        message="Authentication successful"
    )


@router.post("/logout")
@handle_http_exceptions
async def logout_session(
        request: Request,
        logger_obj: AuditLogger = Depends(background_logger),
        revocation_manager: TokenRevocationManager = Depends(get_revocation_manager),
        db: asyncpg.Connection = Depends(get_database_pool)
):
    return await logout(request=request, logger=logger_obj, revocation_manager=revocation_manager, db=db)


@router.get("/refresh")
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


@router.get("/sessions")
@handle_http_exceptions
@handle_database_exceptions
async def list_my_sessions(
        user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
        db: asyncpg.Connection = Depends(get_database_pool)
) -> OrjsonResponse:
    sessions = await get_active_sessions(db, user.user_id, user.tenant_id)
    return success_response(
        data=sessions,
        message=f"Found {len(sessions)} active sessions"
    )


@router.post("/logout-all")
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
        data={"revoked_count": count},
        message=f"Revoked {count} sessions"
    )


@router.post("/logout-others")
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
    from app.core.config import JWT_SECRET
    token = request.headers.get("Authorization", "").split(" ")[-1]
    current_jti = jwt.get_unverified_header(token).get("jti")
    
    count = await revoke_all_sessions(
        db, revocation_manager, user.user_id, user.tenant_id, logger_obj,
        reason="logout_others", exclude_jti=current_jti
    )
    return success_response(
        data={"revoked_count": count},
        message=f"Revoked {count} other sessions"
    )


@router.delete("/sessions/{jti}")
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
    return success_response(data={"revoked": False}, message="Session not found or already revoked")


@router.get("/sessions/all")
@handle_http_exceptions
@handle_database_exceptions
async def list_all_tenant_sessions(
        user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
        db: asyncpg.Connection = Depends(get_database_pool)
) -> OrjsonResponse:
    """List all active sessions for the tenant (admin only)."""
    if user.role not in ("admin", "superadmin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    sessions = await get_all_tenant_sessions(db, user.tenant_id)
    return success_response(
        data=sessions,
        message=f"Found {len(sessions)} active sessions"
    )


@router.get("/sessions/user/{user_id}")
@handle_http_exceptions
@handle_database_exceptions
async def list_user_sessions(
        user_id: str,
        user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
        db: asyncpg.Connection = Depends(get_database_pool)
) -> OrjsonResponse:
    """List all active sessions for a specific user (admin only)."""
    if user.role not in ("admin", "superadmin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    sessions = await get_active_sessions(db, user_id, user.tenant_id)
    return success_response(
        data=sessions,
        message=f"Found {len(sessions)} active sessions for user"
    )


@router.post("/sessions/bulk-revoke")
@handle_http_exceptions
@handle_database_exceptions
async def admin_bulk_revoke(
        request_data: BulkRevokeRequest,
        user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
        db: asyncpg.Connection = Depends(get_database_pool),
        revocation_manager: TokenRevocationManager = Depends(get_revocation_manager),
        logger_obj: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    """Bulk revoke multiple sessions (admin only)."""
    if user.role not in ("admin", "superadmin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    count = await admin_bulk_revoke_sessions(
        db, revocation_manager, request_data.jtis, user.tenant_id, logger_obj
    )
    return success_response(
        data={"revoked_count": count},
        message=f"Revoked {count} sessions"
    )


@router.post("/sessions/user/{user_id}/revoke-all")
@handle_http_exceptions
@handle_database_exceptions
async def admin_revoke_user_sessions(
        user_id: str,
        user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
        db: asyncpg.Connection = Depends(get_database_pool),
        revocation_manager: TokenRevocationManager = Depends(get_revocation_manager),
        logger_obj: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    """Revoke all sessions for a specific user (admin only)."""
    if user.role not in ("admin", "superadmin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    count = await revoke_all_sessions(
        db, revocation_manager, user_id, user.tenant_id, logger_obj, reason="admin_revoke"
    )
    return success_response(
        data={"revoked_count": count},
        message=f"Revoked {count} sessions for user"
    )
