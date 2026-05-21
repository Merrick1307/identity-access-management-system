import time
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any, Optional

from fastapi import Depends, Request
import jwt

from app.audit_logs import AuditLogger, background_logger
from app.core.config import ALGORITHM, JWT_SECRET
from app.core.signing_keys import get_signing_key_manager
from app.exceptions.domain import AuthenticationError, InternalAppError

VerifiedTokenData = namedtuple(
    "VerifiedTokenData",
    [
        "email", "tenant_id", "policy",
        "role", "user_id", "exp", "iat",
        "aud"
    ]
)


def decode_jwt_token(
    token: str,
    *,
    audience: Optional[str] = None,
    verify_aud: bool = False,
    verify_exp: bool = True,
    algorithm: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> dict[str, Any]:
    manager = get_signing_key_manager()
    return manager.decode_token(
        token,
        audience=audience,
        verify_aud=verify_aud,
        options={"verify_exp": verify_exp},
        algorithm=algorithm,
        secret_key=secret_key,
    )


def create_jwt_token(
    payload: dict[str, Any],
    secret_key: Optional[str] = None,
    algorithm: Optional[str] = None,
) -> str:
    user_id = payload.get("user_id") or payload["sub"]
    jti = f"{user_id}-{time.time_ns()}"
    headers = {"jti": jti}
    final_payload = {**payload, "jti": jti}
    return get_signing_key_manager().sign_token(
        final_payload,
        headers=headers,
        algorithm=algorithm,
        secret_key=secret_key,
    )


def create_purpose_token(
    payload: dict[str, Any],
    secret_key: Optional[str] = None,
    algorithm: Optional[str] = None,
) -> str:
    return get_signing_key_manager().sign_token(
        payload,
        algorithm=algorithm,
        secret_key=secret_key,
    )


def decode_purpose_token(
    token: str,
    secret_key: Optional[str] = None,
    algorithm: Optional[str] = None,
    expected_purpose: Optional[str] = None
) -> dict[str, Any]:
    payload = decode_jwt_token(
        token,
        verify_aud=False,
        algorithm=algorithm,
        secret_key=secret_key,
    )
    if expected_purpose and payload.get("purpose") != expected_purpose:
        raise ValueError(f"Invalid token purpose. Expected '{expected_purpose}'")
    return payload


class VerifyToken:
    def __init__(self, logger: AuditLogger):
        self.logger = logger

    def __call__(self, token: str) -> tuple[Optional[str], Optional[int], Optional[VerifiedTokenData]]:
        error_str: Optional[str] = None
        error_code: int = 200
        try:
            payload = decode_jwt_token(token, verify_aud=False, verify_exp=True)

            email: Optional[str] = payload.get("sub")
            tenant_id: Optional[str] = payload.get("tenant_id")
            user_id: Optional[str] = payload.get("user_id") or payload.get("sub")
            role: Optional[str] = payload.get("role")
            policy = payload.get("policy")
            exp = payload.get("exp")
            iat = payload.get("iat")
            aud = payload.get("aud")

            if not email:
                error_str = f"Token missing 'sub' for token: {token[:10]}..."
                error_code = 401
                return error_str, error_code, None
            if not user_id:
                error_str = f"Token missing 'user_id' for token: {token[:10]}..."
                error_code = 401
                return error_str, error_code, None
            if not tenant_id:
                error_str = f"Token missing 'tenant_id' for token: {token[:10]}..."
                error_code = 401
                return error_str, error_code, None

            return error_str, error_code, VerifiedTokenData(
                email=email,
                tenant_id=tenant_id,
                policy=policy,
                role=role,
                user_id=user_id,
                exp=exp,
                iat=iat,
                aud=aud,
            )

        except jwt.ExpiredSignatureError:
            return f"Expired token: {token[:10]}...", 401, None
        except jwt.InvalidSignatureError:
            return f"Invalid signature: {token[:10]}...", 401, None
        except jwt.DecodeError:
            return f"Decode error: {token[:10]}...", 401, None
        except jwt.InvalidTokenError:
            return f"Invalid token: {token[:10]}...", 401, None
        except jwt.InvalidKeyError:
            return "JWT secret key error", 500, None
        except Exception as exc:
            return f"Token error: {type(exc).__name__}: {exc}", 500, None


def extract_token(request: Request) -> tuple[Optional[str], int, Optional[str]]:
    error_str: Optional[str] = None
    error_code: int = 200
    result: Optional[str] = None
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return "Authorization header missing", 401, result
    try:
        scheme, token = auth_header.split(" ", 1)
        if scheme.lower() != "bearer":
            return "Invalid scheme. Expected 'Bearer'", 401, result
        result = token
        return error_str, error_code, result
    except ValueError:
        return "Malformed Authorization header", 401, result
    except Exception as exc:
        return f"Header error: {type(exc).__name__}: {exc}", 500, result


@lru_cache(maxsize=10000)
def cached_verify_token(token: str, logger: AuditLogger) -> VerifiedTokenData:
    error_str, error_code, result = VerifyToken(logger)(token)
    if error_str:
        logger.error(error_str)
        if error_code == 401:
            raise AuthenticationError(error_str)
        raise InternalAppError()
    return result


def verify_and_return_jwt_payload(
    request: Request,
    logger: AuditLogger = Depends(background_logger)
) -> VerifiedTokenData:
    error_str, error_code, token = extract_token(request)
    if token is None:
        logger.error(error_str)
        if error_code == 401:
            raise AuthenticationError(error_str)
        raise InternalAppError()
    return cached_verify_token(token, logger)


def create_verification_token(*, user_id: str, tenant_id: str) -> str:
    payload = {
        "user_id": user_id,
        "tenant_id": tenant_id,
        "purpose": "email_verify",
        "exp": datetime.now(timezone.utc) + timedelta(hours=24),
        "iat": datetime.now(timezone.utc),
    }
    return create_purpose_token(payload, JWT_SECRET, ALGORITHM)
