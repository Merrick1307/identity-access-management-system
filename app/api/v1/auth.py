from typing import Callable, Annotated

import asyncpg
from fastapi import APIRouter, Request, Depends, status
from pydantic import EmailStr
from starlette.responses import JSONResponse

from app.core.auth import authenticate, get_client_ip
from app.core.config import JWT_SECRET
from app.database import get_database_pool
from app.exceptions.database_error_module import handle_database_exceptions
from app.exceptions.http_error_module import handle_http_exceptions
from app.models.auth import Authentication

router: APIRouter = APIRouter()


@router.post("/token")
@handle_http_exceptions
@handle_database_exceptions
async def get_token(
        request: Request,
        auth: Authentication,
        db: asyncpg.Connection = Depends(
            get_database_pool
        )
):
    email: EmailStr = auth.email
    tenant_id: str = auth.tenant_id
    password: str = auth.password
    email_string = str(email)
    ip = get_client_ip(request=request)

    access_token = await authenticate(db=db, ip=ip, email=email_string, tenant_id=tenant_id, password=password)

    return JSONResponse(
        content={"access_token": access_token, "token_type": "Bearer"},
        status_code=status.HTTP_200_OK
    )

