import asyncpg
import jwt
from fastapi import APIRouter, Depends, HTTPException
from pydantic import UUID4

from app.audit_logs import AuditLogger, background_logger
from app.core.config import JWT_SECRET, ALGORITHM
from app.core.responses import success_response, OrjsonResponse
from app.database import get_database_pool, get_database_pool_no_tenant
from app.database.queries import QUERIES
from app.exceptions.database_error_module import handle_database_exceptions
from app.exceptions.http_error_module import handle_http_exceptions
from app.models.onboarding import OnboardingResponse, TenantOnboardingRequest
from app.models.responses import EmailVerificationResponse
from app.models.response_schemas import APIResponseSchema, EmailVerificationResponseSchema, OnboardingResponseSchema
from app.services.onboarding import onboard_tenant

router: APIRouter = APIRouter()


@router.get(
    "/email/verify",
    response_model=APIResponseSchema[EmailVerificationResponseSchema],
    summary="Verify email address",
    description="Verify a user's email address using the token sent via email. "
                "This endpoint is called when user clicks the verification link. "
                "Token expires after 24 hours."
)
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

        await connection.execute(QUERIES["user_verify_email"], user_id, tenant_id)
        logger.audit(
            resource="/email/verify",
            action="Email Verification",
            user_id=user_id,
            tenant_id=tenant_id,
            decision="Email Verified"
        )

        return success_response(
            data= EmailVerificationResponse(),
            message="Email verified successfully"
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=400, detail="Invalid or expired token"
        )


@router.post(
    "/tenant/",
    status_code=201,
    response_model=APIResponseSchema[OnboardingResponseSchema],
    summary="Onboard new tenant",
    description="Create a new tenant organization with root admin user. "
                "Sets up the tenant, creates the admin account, assigns default policies, "
                "and sends verification email. This is the entry point for new organizations."
)
@handle_database_exceptions
async def tenant_onboarding(
    request: TenantOnboardingRequest,
    connection: asyncpg.Connection = Depends(get_database_pool_no_tenant),
    logger: AuditLogger = Depends(
        background_logger
    )
) -> OrjsonResponse:
    result = await onboard_tenant(connection, request, logger)
    user_id: UUID4 = result.get("user_id")
    tenant_id: UUID4 = result.get("tenant_id")
    try:
        response = OnboardingResponse(
            tenant_id=tenant_id,
            user_id=user_id
        )
        return success_response(
            data= response,
            message="Onboarding initiated. Check email for verification."
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
