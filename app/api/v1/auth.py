from typing import Callable

import asyncpg
import jwt
from fastapi import APIRouter, Form, Request, Depends
from pydantic import EmailStr
from starlette.responses import JSONResponse

from app.core.auth import user_login
from app.core.config import JWT_SECRET
from app.database import get_database_pool
from app.exceptions.database_error_module import handle_database_exceptions
from app.exceptions.http_error_module import handle_http_exceptions

router: APIRouter = APIRouter()


@router.post("/token")
@handle_http_exceptions
@handle_database_exceptions
async def get_token(
        request: Request,
        email: EmailStr = Form(...),
        tenant_id: str = Form(...),
        password: str = Form(...),
        db: asyncpg.Connection = Depends(
            get_database_pool
        )
):
    prob_ip = request.client.host
    ip = request.headers.get("X-Forwarded-For", prob_ip)
    email_string = str(email)

    access_token = await user_login(
        ip=ip, email=email_string, tenant_id=tenant_id, password=password,
        db=db
    )

    return JSONResponse(
        {"access_token": access_token, "token_type": "Bearer"},
    )


class VerifyToken:

    def __call__(self, request: Request) -> Callable:
        self.token: str = request.headers.get("Authorization").split(" ")[-1]

        async def verify_token():
            try:
                payload = jwt.decode(token=self.token, key=JWT_SECRET, algorithms=["HS256"])
                email: str = payload.get("sub")
                tenant_id: str = payload.get("tenant_id")
                user_id: str = payload.get("user_id")
                role: str = payload.get("role")
                policy = payload.get("policy")
                exp = payload.get("exp")
            except jwt.ExpiredSignatureError:
                pass
            except jwt.DecodeError:
                pass
            except jwt.InvalidTokenError:
                pass
            except jwt.PyJWTError:
                pass
