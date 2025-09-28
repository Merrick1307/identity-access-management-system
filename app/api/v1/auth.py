import asyncpg
from fastapi import APIRouter, Request, Depends, status, BackgroundTasks
from pydantic import EmailStr
from rbloom import Bloom
from starlette.responses import JSONResponse

from app.audit_logs import AuditLogger, background_logger
from app.core.auth import authenticate, get_client_ip, logout, refresh
from app.database import get_database_pool, get_bloom
from app.exceptions.database_error_module import handle_database_exceptions
from app.exceptions.http_error_module import handle_http_exceptions
from app.models.auth import Authentication

router: APIRouter = APIRouter()


@router.post("/token")
@handle_database_exceptions
async def get_token(
        request: Request,
        auth: Authentication,
        background_tasks: BackgroundTasks,
        logger_obj: AuditLogger = Depends(background_logger),
        db: asyncpg.Connection = Depends(
            get_database_pool
        )
):
    email: EmailStr = auth.email
    tenant_id: str = request.headers.get("X-TENANT-ID")
    password: str = auth.password
    email_string = str(email)
    ip = get_client_ip(request=request)

    access_token = await authenticate(
        db=db, ip=ip, email=email_string, tenant_id=tenant_id,
        password=password, logger_obj=logger_obj
    )

    return JSONResponse(
        content={"access_token": access_token, "token_type": "Bearer"},
        status_code=status.HTTP_200_OK
    )


@router.post("/logout")
@handle_http_exceptions
async def logout_session(
        request: Request,
        logger_obj: AuditLogger = Depends(background_logger),
        bloom = Depends(get_bloom)
):
    return await logout(request=request, logger=logger_obj, bloom_f=bloom)


@router.get("/refresh")
@handle_http_exceptions
async def refresh_session(
        request: Request,
        logger_obj: AuditLogger = Depends(background_logger),
        bloom: Bloom = Depends(get_bloom),
        db_pool: asyncpg.Connection = Depends(get_database_pool)
)-> JSONResponse:
    return await refresh(
        request=request,
        logger=logger_obj,
        bloom_f=bloom,
        db_pool=db_pool
    )
