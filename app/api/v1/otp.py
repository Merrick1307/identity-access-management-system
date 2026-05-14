import asyncpg
from fastapi import APIRouter
from fastapi.params import Depends

from app.core.config import ENCRYPT_KEY
from app.core.jwt_utils import VerifiedTokenData, verify_and_return_jwt_payload
from app.core.responses import success_response
from app.database import get_database_pool
from app.models.responses import OTPVerifyResponse
from app.models.response_schemas import APIResponseSchema, OTPProvisionResponseSchema, OTPVerifyResponseSchema
from app.services.otp_service import OTPService

router: APIRouter = APIRouter()


@router.post(
    "/otp",
    response_model=APIResponseSchema[OTPProvisionResponseSchema],
    summary="Provision TOTP for MFA",
    description="Generate a new TOTP secret for the current user. Returns the secret, "
                "provisioning URI (for QR code), and backup codes. Store these securely - "
                "they are shown only once. Requires MFA to be enabled for the tenant."
)
async def register_otp(
        current_user: VerifiedTokenData = Depends(
            verify_and_return_jwt_payload
        ),
        db: asyncpg.Connection = Depends(
            get_database_pool
        )
):
    otp_service = OTPService(encrypt_key=ENCRYPT_KEY)
    result = await otp_service.provision_stateless_otp(
        db=db,
        tenant_id=current_user.tenant_id,
        user_email=current_user.email,
        aud=current_user.aud
    )
    return success_response(data=result, message="OTP provisioned successfully")


@router.post(
    "/otp/verify",
    response_model=APIResponseSchema[OTPVerifyResponseSchema],
    summary="Verify TOTP code",
    description="Verify a 6-digit TOTP code from the user's authenticator app. "
                "Returns verification status. Use during login or for sensitive operations."
)
async def verify_otp(
        otp_code: str,
        current_user: VerifiedTokenData = Depends(
            verify_and_return_jwt_payload
        ),
        db: asyncpg.Connection = Depends(
            get_database_pool
        )
):
    otp_service = OTPService(encrypt_key=ENCRYPT_KEY)
    response = await otp_service.verify_otp(
        db=db,
        otp_code=otp_code,
        tenant_id=current_user.tenant_id,
        user_email=current_user.email,
        aud=current_user.aud
    )
    return success_response(data=OTPVerifyResponse(verified=response), message="OTP verified successfully")
