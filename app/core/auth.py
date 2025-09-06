from datetime import datetime, timezone, timedelta

import asyncpg
import bcrypt
from email_validator import validate_email
from fastapi import HTTPException, status, Depends, Request
from jwt import PyJWTError

from app.audit_logs import AuditLogger, background_logger
from app.core.config import JWT_SECRET
from app.core.jwt_utils import create_jwt_token
from app.core.queries import fetch_user, fetch_user_policy
from app.models.authz import Action


async def authenticate(
        db: asyncpg.Connection,
        ip: str,
        email: str,
        tenant_id: str,
        password: str,
        logger_obj: AuditLogger = Depends(background_logger)
):
    try:
        normalized_email = validate_email(
            email, check_deliverability=True
        )

        user_data = await db.fetchval(fetch_user, normalized_email, tenant_id)

        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Invalid email or password"
            )

        hashed_password: str = user_data.get("password")

        valid_password = bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))
        if not valid_password:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Invalid email or password"
            )

        tenant_user_policy = await db.fetchrow(fetch_user_policy, normalized_email, tenant_id)
        policy = tenant_user_policy["policy"]
        user_policy = {
                p["resource"]: sum(Action[a.upper()] for a in p["actions"])
                for p in policy
        }

        payload = {
            "sub": normalized_email,
            "user_id": user_data["user_id"],
            "tenant_id": tenant_id,
            "role": tenant_user_policy["role"],
            "policy": user_policy,
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        }

        return await create_jwt_token(payload=payload, secret_key=JWT_SECRET)

    except PyJWTError:
        await logger_obj.force_error(
            message=f"Suspicious authentication attempt from IP: {ip}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unexpected authorization error"
        )
    except Exception:
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


async def logout():
    pass
