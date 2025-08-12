import asyncpg
from fastapi import APIRouter, Form, Request, Depends
from pydantic import EmailStr
from starlette.responses import JSONResponse

from app.core.auth import user_login
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
