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
        "role", "user_id", "exp", "iat"
    ]
)


async def create_jwt_token(payload: dict, secret_key: str):
    user_id = payload['user_id']
    headers = {
        "jti": f"{user_id}-{time.time_ns()}",
    }
    jwt_token = jwt.encode(
        payload, secret_key, algorithm='HS256', headers=headers
    )
    return jwt_token


class VerifyToken:
    def __init__(self, logger: AuditLogger):
        self.logger = logger

    def __call__(self, token: str) -> VerifiedTokenData:  # SYNC for cache speed
        """
        Verify JWT synchronously - offload async logs to tasks.
        """
        try:
            # Decode and verify (unchanged)
            payload = jwt.decode(
                jwt=token,
                key=JWT_SECRET,
                algorithms=["HS256"],
                options={"verify_exp": True}
            )

            # Extract fields (unchanged)
            email: Optional[str] = payload.get("sub")
            tenant_id: Optional[str] = payload.get("tenant_id")
            user_id: Optional[str] = payload.get("user_id")
            role: Optional[str] = payload.get("role")
            policy = payload.get("policy")
            exp = payload.get("exp")
            iat = payload.get("iat")

            # Validate with OFFLOADED LOGS (NO AWAIT!)
            if not email:
                asyncio.create_task(  # FIRE-AND-FORGET!
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
                user_id=user_id,
                role=role,
                policy=policy,
                exp=exp,
                iat=iat
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

