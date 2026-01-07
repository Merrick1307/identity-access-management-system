import time
from collections import namedtuple
from functools import lru_cache
from typing import Callable, Dict, Any, Optional
from fastapi import Request, HTTPException, status, Depends
import asyncio

import jwt
from starlette.background import BackgroundTasks

from app.audit_logs import AuditLogger, background_logger
from app.core.config import JWT_SECRET

VerifiedTokenData = namedtuple(
    "VerifiedTokenData",
    [
        "email", "tenant_id", "policy",
        "role", "user_id", "exp", "iat",
        "aud"
    ]
)


async def create_jwt_token(payload: dict, secret_key: str):
    user_id = payload.get('user_id') or payload['sub']
    headers = {
        "jti": f"{user_id}-{time.time_ns()}",
    }
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

    def __call__(self, token: str) -> VerifiedTokenData:
        """
        Verify JWT - offload async logs to tasks.
        """
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
                asyncio.create_task(  # FIRE-AND-FORGET
                    self.logger.force_warning(
                        f"Token missing 'sub' for token: {token[:10]}..."
                    )
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token missing required 'sub' field"
                )
            if not user_id:
                asyncio.create_task(
                    self.logger.force_warning(
                        f"Token missing 'user_id' for token: {token[:10]}..."
                    )
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token missing required 'user_id' field"
                )
            if not tenant_id:
                asyncio.create_task(
                    self.logger.force_warning(
                        f"Token missing 'tenant_id' for token: {token[:10]}..."
                    )
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token missing required 'tenant_id' field"
                )

            return VerifiedTokenData(
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
            asyncio.create_task(
                self.logger.force_warning(f"Expired token: {token[:10]}...")
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except jwt.InvalidSignatureError:
            asyncio.create_task(
                self.logger.force_warning(f"Invalid signature: {token[:10]}...")
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token signature"
            )
        except jwt.DecodeError:
            asyncio.create_task(
                self.logger.force_warning(f"Decode error: {token[:10]}...")
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token format"
            )
        except jwt.InvalidTokenError:
            asyncio.create_task(
                self.logger.force_warning(f"Invalid token: {token[:10]}...")
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        except jwt.InvalidKeyError:
            asyncio.create_task(
                self.logger.force_error("JWT secret key error")
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Server configuration error"
            )
        except (ValueError, Exception) as e:  # Catch-all
            asyncio.create_task(
                self.logger.force_warning(f"Token error: {type(e).__name__}: {str(e)}")
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED if "Invalid" in str(
                    e) else status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Invalid token data" if "Invalid" in str(e) else "Internal server error"
            )


async def extract_token(request: Request, logger: AuditLogger = Depends(background_logger)) -> str:
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        await logger.force_error("Authorization header missing")  # Rare - await OK here
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing"
        )
    try:
        scheme, token = auth_header.split(" ", 1)
        if scheme.lower() != "bearer":
            await logger.force_error("Invalid scheme. Expected 'Bearer'")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication scheme. Expected 'Bearer'"
            )
        return token
    except ValueError:
        await logger.force_error("Malformed Authorization header")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed Authorization header. Expected 'Bearer <token>'"
        )
    except Exception as e:
        await logger.force_error(f"Header error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


# CACHED VERIFY (TOKEN KEY)
@lru_cache(maxsize=10000)
def cached_verify_token(token: str) -> VerifiedTokenData:
    """SYNC cached verify - logger injected via init"""
    background_tasks = BackgroundTasks()
    logger = background_logger(background_tasks)
    return VerifyToken(logger)(token)


async def verify_and_return_jwt_payload(
        request: Request,
        logger: AuditLogger = Depends(background_logger)
) -> VerifiedTokenData:
    token = await extract_token(request, logger)
    return cached_verify_token(token)
