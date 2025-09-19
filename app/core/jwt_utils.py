import time
from collections import namedtuple
from typing import Callable, Dict, Any, Optional
from fastapi import Request, HTTPException, status, Depends

import jwt

from app.audit_logs import AuditLogger, get_audit_logger, background_logger
from app.core.config import JWT_SECRET

VerifiedTokenData = namedtuple(
    "VerifiedTokenData",
    [
        "email", "tenant_id", "policy",
        "role", "user_id", "exp"
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

    async def __call__(self, request: Request) -> VerifiedTokenData:
        """
        Extract and verify JWT token from request headers asynchronously.
        Logs errors using the injected logger before raising exceptions.
        """
        # Handle missing Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            await self.logger.force_error("Authorization header missing")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization header missing"
            )

        # Handle malformed Authorization header
        try:
            scheme, token = auth_header.split(" ", 1)
            if scheme.lower() != "bearer":
                await self.logger.force_error("Invalid authentication scheme. Expected 'Bearer'")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication scheme. Expected 'Bearer'"
                )
            self.token = token
        except ValueError:
            await self.logger.force_error("Malformed Authorization header. Expected 'Bearer <token>'")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Malformed Authorization header. Expected 'Bearer <token>'"
            )
        except Exception as e:
            # Catch any unexpected errors in header processing
            await self.logger.force_error(f"Unexpected error processing Authorization header: {type(e).__name__}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )

        # Decode and verify the JWT token
        try:
            # Decode and verify the JWT token
            payload = jwt.decode(
                jwt=self.token,
                key=JWT_SECRET,
                algorithms=["HS256"],
                options={"verify_exp": True}  # Explicitly verify expiration
            )

            # Extract and validate required fields
            email: Optional[str] = payload.get("sub")
            tenant_id: Optional[str] = payload.get("tenant_id")
            user_id: Optional[str] = payload.get("user_id")
            role: Optional[str] = payload.get("role")
            policy = payload.get("policy")
            exp = payload.get("exp")

            # Validate required fields are present
            if not email:
                await self.logger.force_warning(
                    f"Token missing required 'sub' field for token: {self.token[:10]}..."
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token missing required 'sub' field"
                )

            if not user_id:
                await self.logger.force_warning(
                    f"Token missing required 'user_id' field for token: {self.token[:10]}..."
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token missing required 'user_id' field"
                )

            if not tenant_id:
                await self.logger.force_warning(
                    f"Token missing required 'tenant_id' field for token: {self.token[:10]}..."
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
                exp=exp
            )

        except jwt.ExpiredSignatureError:
            await self.logger.force_warning(f"Expired token attempt for token: {self.token[:10]}...")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )

        except jwt.InvalidSignatureError:
            await self.logger.force_warning(f"Invalid signature for token: {self.token[:10]}...")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token signature"
            )

        except jwt.DecodeError:
            await self.logger.force_warning(f"Token decode error for token: {self.token[:10]}...")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token format"
            )

        except jwt.InvalidTokenError:
            # This is a broader category that catches other JWT-related errors
            await self.logger.force_warning(f"Invalid token error for token: {self.token[:10]}...")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )

        except jwt.InvalidKeyError:
            await self.logger.force_error("JWT secret key configuration error")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Server configuration error"
            )

        except ValueError as e:
            # Any potential issues with payload processing
            await self.logger.force_warning(f"Value error during token processing: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token data"
            )

        except Exception as e:
            await self.logger.force_error(f"Unexpected error during token verification: {type(e).__name__}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error during authentication"
            )


async def verify_and_return_jwt_payload(
    request: Request,
    logger: AuditLogger = Depends(background_logger)
) -> VerifiedTokenData:
    return await VerifyToken(logger)(request)
