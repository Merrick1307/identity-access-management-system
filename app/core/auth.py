import asyncio
import json
import sys
from datetime import datetime, timezone, timedelta

import asyncpg
import bcrypt
import jwt
import rbloom
from email_validator import validate_email
from fastapi import HTTPException, status, Request, Depends
from jwt import PyJWTError
from rbloom.rbloom import Bloom
from starlette.responses import JSONResponse

from app.audit_logs import AuditLogger
from app.core.config import JWT_SECRET
from app.core.jwt_utils import create_jwt_token
from app.core.queries import fetch_user, fetch_user_policy, fetch_user_with_policy, check_modified
from app.database import get_bloom
from app.models.authz import Action


async def authenticate(
        db: asyncpg.Connection,
        ip: str,
        email: str,
        tenant_id: str,
        password: str,
        logger_obj: AuditLogger
):
    try:
        normalized_email = validate_email(
            email, check_deliverability=False
        ).normalized
        user_data = await db.fetch(fetch_user_with_policy, normalized_email)
        persona = user_data[0]

        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invalid email"
            )
        user_id: str = persona["id"]

        hashed_password: str = persona.get("password")

        valid_password = bcrypt.checkpw(
            password.encode("utf-8"), hashed_password.encode("utf-8")
        )
        if not valid_password:
            await logger_obj.force_error(
                message=f"Suspicious authentication attempt from IP: {ip}"
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invalid credentials"
            )

        policies = []
        if user_data:  # More pythonic than checking len() != 0
            policies = [json.loads(row["policy"]) for row in user_data]
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

        access_token = await create_jwt_token(payload=payload, secret_key=JWT_SECRET)
        if access_token:
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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unexpected authorization error"
        )
    except Exception:
        await logger_obj.log_exception(
            context="Unexpected Error on authentication",
            func_name=sys._getframe().f_code.co_name,
            exception=Exception(sys.exc_info()),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP if multiple proxies
        return forwarded_for.split(",")[0].strip()
    return request.client.host or "unknown"


async def logout(
        request: Request,
        logger: AuditLogger,
        bloom_f
):
    # Extract and validate Authorization header
    token_header = request.headers.get("Authorization")
    if not token_header:
        await logger.force_error("Invalid authorization header: Missing")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid authorization header"
        )

    try:
        scheme, token = token_header.split(" ", 1)
        if scheme.lower() != "bearer":
            await logger.force_error("Invalid authentication scheme: Expected 'Bearer'")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid authentication scheme. Expected 'Bearer'"
            )
        token_header_jti = jwt.get_unverified_header(token).get("jti")

    except ValueError:
        await logger.force_error("Malformed Authorization header: Expected 'Bearer <token>'")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed Authorization header. Expected 'Bearer <token>'"
        )
    except Exception as e:
        await logger.force_error(f"Unexpected error processing Authorization header: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

    # Blacklist token
    try:
        await asyncio.to_thread(
            bloom_f.add,token_header_jti
        )
        logger.audit(
            action="logout",
            resource="/logout",
            ip=get_client_ip(request),
            decision="Logged out, Token blacklisted"
        )
    except Exception as e:
        await logger.force_error(f"Failed to blacklist token: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to blacklist token"
        )

    return JSONResponse(
        content={"message": "Successfully logged out"},
        status_code=status.HTTP_200_OK
    )


async def refresh(
        request: Request,
        logger: AuditLogger,
        db_pool: asyncpg.Connection,
        bloom_f: Bloom
):
    refresh_token = request.headers.get("X-Refresh-Token")

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid authorization header"
        )
    scheme, token = refresh_token.split(" ", 1)

    if scheme.lower() != "refresh":
        logger.error("Invalid authentication scheme: Expected 'Refresh'")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid authentication scheme. Expected 'Refresh'"
        )
    decoded_token = jwt.decode(
        token, JWT_SECRET, ['HS256'], {"verify_exp": True}
    )
    email: str = decoded_token.get("email")

    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header"
        )

    iat = decoded_token.get("iat")
    if not iat:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed authorization header"
        )

    normalized_email = validate_email(
        email, check_deliverability=False
    ).normalized
    modified_deets = await db_pool.fetchval(check_modified, normalized_email, iat)

    if modified_deets:
        token_header_jti = jwt.get_unverified_header(token).get("jti")
        await asyncio.to_thread(
            bloom_f.add, token_header_jti
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="sensitive profile info updated, login again"
        )
    new_iat = datetime.now(timezone.utc)
    decoded_token.update({"iat": new_iat})
    refresh_token = create_jwt_token(decoded_token, JWT_SECRET)

    user_data = await db_pool.fetch(fetch_user_with_policy, normalized_email)

    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid email"
        )
    persona = user_data[0]
    user_id: str = persona.get("id")
    tenant_id: str = request.headers.get("X-TENANT-ID")
    policies = [json.loads(row["policy"]) for row in user_data if row.get("policy")]
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

    access_token = await create_jwt_token(payload=payload, secret_key=JWT_SECRET)
    ip: str = get_client_ip(request)

    logger.audit(
        action="refresh authentication",
        user_id=user_id,
        resource="/refresh",
        ip=ip,
        decision="Authenticated"
    )

    return JSONResponse(
        content={
            "access_token": access_token,
            "refresh_token": refresh_token
        },
        status_code=status.HTTP_200_OK
    )