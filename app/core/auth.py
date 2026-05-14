import asyncio
import sys
from datetime import datetime, timezone, timedelta
from typing import Optional, TYPE_CHECKING

import orjson

import asyncpg
import jwt
from email_validator import validate_email
from fastapi import Request
from jwt import PyJWTError

from app.audit_logs import AuditLogger
from app.core.responses import success_response
from app.core.config import JWT_SECRET
from app.core.jwt_utils import create_jwt_token
from app.core.queries import fetch_user_with_policy, check_modified
from app.core.security import verify_password
from app.exceptions.domain import (
    AppError,
    AuthenticationError,
    AuthorizationError,
    BusinessValidationError,
    InternalAppError,
)
from app.models.authz import Action
from app.services.session_service import create_session, revoke_session

if TYPE_CHECKING:
    from app.core.token_revocation import TokenRevocationManager


async def authenticate(
        db: asyncpg.Connection,
        ip: str,
        email: str,
        tenant_id: str,
        password: str,
        logger_obj: AuditLogger,
        device_info: Optional[dict] = None
):
    try:
        normalized_email = validate_email(
            email, check_deliverability=False
        ).normalized
        user_data = await db.fetch(fetch_user_with_policy, normalized_email)

        if not user_data:
            raise AuthenticationError("Invalid credentials")
        persona = user_data[0]

        if not persona:
            raise AuthenticationError("Invalid credentials")
        user_id: str = persona["id"]

        hashed_password: str = persona.get("password")

        if not await asyncio.to_thread(verify_password, password, hashed_password):
            await logger_obj.force_error(
                message=f"Suspicious authentication attempt from IP: {ip}"
            )
            raise AuthenticationError("Invalid credentials")

        policies = []
        if user_data:  # More pythonic than checking len() != 0
            policies = [orjson.loads(row["policy"]) for row in user_data]
        user_policy = {
            p["resource"]: sum(Action[a.upper()] for a in p["actions"])
            for p in policies
        }

        payload = {
            "sub": normalized_email,
            "user_id": user_id,
            "tenant_id": tenant_id,
            "role": persona["role"],
            "policy": user_policy,
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        }

        access_token = create_jwt_token(payload=payload, secret_key=JWT_SECRET)
        if access_token:
            jti = jwt.get_unverified_header(access_token).get("jti")
            await create_session(
                db=db,
                jti=jti,
                user_id=user_id,
                tenant_id=tenant_id,
                expires_at=payload["exp"],
                ip_address=ip,
                device_info=device_info
            )
            logger_obj.audit(
                action="authentication",
                user_id=user_id,
                resource="/token",
                ip=ip,
                decision="Authenticated"
            )
            return access_token

    except PyJWTError:
        await logger_obj.force_error(
            message=f"Suspicious authentication attempt from IP: {ip}"
        )
        await logger_obj.log_exception(
            message=f"Suspicious authentication attempt from IP: {ip}",
            context="JWT Error",
            func_name=sys._getframe().f_code.co_name,
            exception=Exception(sys.exc_info()),
        )
        raise AuthenticationError("Unexpected authorization error")
    except AppError:
        raise
    except Exception:
        await logger_obj.log_exception(
            context="Unexpected Error on authentication",
            func_name=sys._getframe().f_code.co_name,
            exception=Exception(sys.exc_info()),
        )
        raise InternalAppError()


def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP if multiple proxies
        return forwarded_for.split(",")[0].strip()
    return request.client.host or "unknown"


async def logout(
        request: Request,
        logger: AuditLogger,
        revocation_manager: "TokenRevocationManager",
        db: asyncpg.Connection
):
    token_header = request.headers.get("Authorization")
    if not token_header:
        await logger.force_error("Invalid authorization header: Missing")
        raise BusinessValidationError("Invalid authorization header")

    try:
        scheme, token = token_header.split(" ", 1)
        if scheme.lower() != "bearer":
            await logger.force_error("Invalid authentication scheme: Expected 'Bearer'")
            raise BusinessValidationError("Invalid authentication scheme. Expected 'Bearer'")
        token_header_jti = jwt.get_unverified_header(token).get("jti")
        decoded = jwt.decode(token, JWT_SECRET, ["HS256"], {"verify_exp": False})
        user_id = decoded.get("user_id")
        tenant_id = decoded.get("tenant_id")

    except ValueError:
        await logger.force_error("Malformed Authorization header: Expected 'Bearer <token>'")
        raise BusinessValidationError("Malformed Authorization header. Expected 'Bearer <token>'")
    except AppError:
        raise
    except Exception as e:
        await logger.force_error(f"Unexpected error processing Authorization header: {type(e).__name__}: {str(e)}")
        raise InternalAppError()

    try:
        await revoke_session(db, revocation_manager, token_header_jti, user_id, tenant_id, "logout")
        logger.audit(
            action="logout",
            user_id=user_id,
            resource="/logout",
            ip=get_client_ip(request),
            decision="Logged out, Token blacklisted"
        )
    except Exception as e:
        await logger.force_error(f"Failed to blacklist token: {type(e).__name__}: {str(e)}")
        raise InternalAppError("Failed to blacklist token")

    return success_response(data={"logged_out": True}, message="Successfully logged out")


async def refresh(
        request: Request,
        logger: AuditLogger,
        db_pool: asyncpg.Connection,
        revocation_manager: "TokenRevocationManager"
):
    refresh_token = request.headers.get("X-Refresh-Token")

    if not refresh_token:
        raise BusinessValidationError("Invalid authorization header")
    try:
        scheme, token = refresh_token.split(" ", 1)
    except ValueError:
        raise BusinessValidationError("Malformed authorization header")

    if scheme.lower() != "refresh":
        logger.error("Invalid authentication scheme: Expected 'Refresh'")
        raise BusinessValidationError("Invalid authentication scheme. Expected 'Refresh'")
    try:
        decoded_token = jwt.decode(
            token, JWT_SECRET, ['HS256'], {"verify_exp": True}
        )
    except PyJWTError:
        raise AuthenticationError("Invalid refresh token")
    email: str = decoded_token.get("email")

    if not email:
        raise AuthenticationError("Invalid authorization header")

    iat = decoded_token.get("iat")
    if not iat:
        raise BusinessValidationError("Malformed authorization header")

    normalized_email = validate_email(
        email, check_deliverability=False
    ).normalized
    modified_deets = await db_pool.fetchval(check_modified, normalized_email, iat)

    if modified_deets:
        token_header_jti = jwt.get_unverified_header(token).get("jti")
        tenant_id = request.headers.get("X-TENANT-ID", "unknown")
        user_id = decoded_token.get("user_id", "unknown")
        await revocation_manager.revoke_token(token_header_jti, user_id, tenant_id, "profile_modified")
        raise AuthorizationError("Sensitive profile info updated, login again")
    new_iat = datetime.now(timezone.utc)
    decoded_token.update({"iat": new_iat})
    refresh_token = create_jwt_token(decoded_token, JWT_SECRET)

    user_data = await db_pool.fetch(fetch_user_with_policy, normalized_email)

    if not user_data:
        raise AuthenticationError("Invalid credentials")
    persona = user_data[0]
    user_id: str = persona.get("id")
    tenant_id: str = request.headers.get("X-TENANT-ID")
    policies = [orjson.loads(row["policy"]) for row in user_data if row.get("policy")]
    user_policy = {
        p["resource"]: sum(Action[a.upper()] for a in p["actions"])
        for p in policies
    }

    payload = {
        "sub": normalized_email,
        "user_id": user_id,
        "tenant_id": tenant_id,
        "role": persona["role"],
        "policy": user_policy,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    }

    access_token = create_jwt_token(payload=payload, secret_key=JWT_SECRET)
    ip: str = get_client_ip(request)

    logger.audit(
        action="refresh authentication",
        user_id=user_id,
        resource="/refresh",
        ip=ip,
        decision="Authenticated"
    )

    return success_response(
        data={"access_token": access_token, "refresh_token": refresh_token},
        message="Token refreshed successfully"
    )
