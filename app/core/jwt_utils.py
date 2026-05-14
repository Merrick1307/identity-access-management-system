import time
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Callable, Dict, Any, Optional
from fastapi import Request, Depends

import jwt

from app.audit_logs import AuditLogger, background_logger
from app.core.config import JWT_SECRET, ALGORITHM
from app.exceptions.domain import AuthenticationError, InternalAppError

VerifiedTokenData = namedtuple(
    "VerifiedTokenData",
    [
        "email", "tenant_id", "policy",
        "role", "user_id", "exp", "iat",
        "aud"
    ]
)


def create_jwt_token(payload: dict, secret_key: str):
    user_id = payload.get('user_id') or payload['sub']
    jti: str = f"{user_id}-{time.time_ns()}"
    headers = {
        "jti": jti,
    }
    payload = {**payload, "jti": jti}
    jwt_token = jwt.encode(
        payload, secret_key, algorithm='HS256', headers=headers
    )
    return jwt_token


def create_purpose_token(
    payload: dict,
    secret_key: str,
    algorithm: str = "HS256"
) -> str:
    """
    Create a stateless JWT for specific purposes (verification, invitation, etc.)
    Unlike create_jwt_token, this doesn't require user_id and doesn't add jti header.
    
    Args:
        payload: Token payload (should include 'purpose', 'exp', 'iat')
        secret_key: JWT signing secret
        algorithm: Signing algorithm (default HS256)
    
    Returns:
        Encoded JWT string
    """
    return jwt.encode(payload, secret_key, algorithm=algorithm)


def decode_purpose_token(
    token: str,
    secret_key: str,
    algorithm: str = "HS256",
    expected_purpose: Optional[str] = None
) -> dict:
    """
    Decode and validate a purpose token.
    
    Args:
        token: JWT token string
        secret_key: JWT signing secret
        algorithm: Signing algorithm
        expected_purpose: If provided, validates the 'purpose' claim matches
    
    Returns:
        Decoded payload dict
        
    Raises:
        jwt.PyJWTError: If token is invalid or expired
        ValueError: If purpose doesn't match expected
    """
    payload = jwt.decode(token, secret_key, algorithms=[algorithm])
    
    if expected_purpose and payload.get("purpose") != expected_purpose:
        raise ValueError(f"Invalid token purpose. Expected '{expected_purpose}'")
    
    return payload


class VerifyToken:
    def __init__(self, logger: AuditLogger):
        self.logger = logger

    def __call__(self, token: str) -> tuple[Optional[str], Optional[int], Optional[VerifiedTokenData]]:
        """
        Verify JWT - offload async logs to tasks.
        """
        error_str: Optional[str] = None
        error_code: int = 200
        try:
            payload = jwt.decode(
                jwt=token,
                key=JWT_SECRET,
                algorithms=["HS256"],
                options={"verify_exp": True}
            )

            # Extract fields
            email: Optional[str] = payload.get("sub")
            tenant_id: Optional[str] = payload.get("tenant_id")
            user_id: Optional[str] = payload.get("user_id") or payload.get("sub")
            role: Optional[str] = payload.get("role")
            policy = payload.get("policy")
            exp = payload.get("exp")
            iat = payload.get("iat")
            aud: Optional[str] = payload.get("aud")

            if not email:
                error_str: str = f"Token missing 'sub' for token: {token[:10]}..."
                error_code: int = 401
                return error_str, error_code, None
            if not user_id:
                error_str: str = f"Token missing 'user_id' for token: {token[:10]}..."
                error_code: int = 401
                return error_str, error_code, None
            if not tenant_id:
                error_str: str = f"Token missing 'tenant_id' for token: {token[:10]}..."
                error_code: int = 401
                return error_str, error_code, None

            return error_str, error_code, VerifiedTokenData(
                email=email,
                tenant_id=tenant_id,
                policy=policy,
                role=role,
                user_id=user_id,
                exp=exp,
                iat=iat,
                aud=aud
            )

        except jwt.ExpiredSignatureError:
            error_str: str = f"Expired token: {token[:10]}..."
            error_code: int = 401
            return error_str, error_code, None
        except jwt.InvalidSignatureError:
            error_str: str = f"Invalid signature: {token[:10]}..."
            error_code: int = 401
            return error_str, error_code, None
        except jwt.DecodeError:
            error_str: str = f"Decode error: {token[:10]}..."
            error_code: int = 401
            return error_str, error_code, None
        except jwt.InvalidTokenError:
            error_str: str = f"Invalid token: {token[:10]}..."
            error_code: int = 401
            return error_str, error_code, None
        except jwt.InvalidKeyError:
            error_str: str = "JWT secret key error"
            error_code: int = 500
            return error_str, error_code, None
        except (ValueError, Exception) as e:  # Catch-all
            error_str: str = f"Token error: {type(e).__name__}: {str(e)}"
            error_code: int = 500
            return error_str, error_code, None


def extract_token(
        request: Request,
        # logger: AuditLogger = Depends(background_logger)
) -> tuple[Optional[str], int, Optional[str]]:
    error_str: Optional[str] = None
    error_code: int = 200
    result: Optional[str] = None
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        error_str = "Authorization header missing"
        error_code = 401
        return error_str, error_code, result
    try:
        scheme, token = auth_header.split(" ", 1)
        if scheme.lower() != "bearer":
            error_str = "Invalid scheme. Expected 'Bearer'"
            error_code = 401
            return error_str, error_code, result
        result = token
        return error_str, error_code, result
    except ValueError:
        error_str = "Malformed Authorization header"
        error_code = 401
        return error_str, error_code, result
    except Exception as e:
        error_str = f"Header error: {type(e).__name__}: {str(e)}"
        error_code = 500
        return error_str, error_code, result


# CACHED VERIFY (TOKEN KEY)
@lru_cache(maxsize=10000)
def cached_verify_token(token: str, logger: AuditLogger) -> VerifiedTokenData:
    """SYNC cached verify - logger injected via init"""
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
    """
    Create a JWT token for email verification.

    Args:
        user_id: The user's ID
        tenant_id: The tenant's ID

    Returns:
        Encoded JWT token string
    """
    payload = {
        "user_id": user_id,
        "tenant_id": tenant_id,
        "purpose": "email_verify",
        "exp": datetime.now(timezone.utc) + timedelta(hours=24),
        "iat": datetime.now(timezone.utc),
    }
    return create_purpose_token(payload, JWT_SECRET, ALGORITHM or "HS256")
