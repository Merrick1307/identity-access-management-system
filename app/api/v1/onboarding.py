import asyncpg
import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import UUID4
from starlette.responses import JSONResponse

from app.audit_logs import AuditLogger, background_logger
from app.core.config import JWT_SECRET, ALGORITHM
from app.database import get_database_pool
from app.exceptions.database_error_module import handle_database_exceptions
from app.exceptions.http_error_module import handle_http_exceptions
from app.models.onboarding import OnboardingResponse, TenantOnboardingRequest
from app.services.onboarding import onboard_tenant

router: APIRouter = APIRouter()


@router.get("/email/verify")
@handle_http_exceptions
async def verify_email(
        token: str,
        connection: asyncpg.Connection = Depends(get_database_pool),
        logger: AuditLogger = Depends(background_logger)
):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        user_id = payload["user_id"]
        tenant_id = payload["tenant_id"]

        await connection.execute(
            """UPDATE users 
                     SET email_verified = TRUE 
                     WHERE id = $1 
                       AND tenant_id = $2
            """,
            user_id, tenant_id
        )
        logger.audit(
            resource="/email/verify",
            action="Email Verification",
            user_id=user_id,
            tenant_id=tenant_id,
            decision="Email Verified"
        )

        return JSONResponse(
            content={
                "message": "Email verified successfully. You can now log in."
            }, status_code=status.HTTP_200_OK
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=400, detail="Invalid or expired token"
        )


@router.post("/tenant/",  response_model=OnboardingResponse, status_code=201)
@handle_database_exceptions
async def tenant_onboarding(
    request: TenantOnboardingRequest,
    connection: asyncpg.Connection = Depends(get_database_pool),
    logger: AuditLogger = Depends(
        background_logger
    )
):
    try:
        result = await onboard_tenant(connection, request, logger)
        user_id: UUID4 = result.get("user_id")
        tenant_id: UUID4 = result.get("tenant_id")
        return OnboardingResponse(
            tenant_id=tenant_id,
            user_id=user_id
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if tenant_id:
            logger.audit(
                user_id=user_id,
                tenant_id=tenant_id,
                resource="/tenant/onboarding",
                action="onboarding",
                decision="New Tenant Onboarded"
            )
        else:
            pass