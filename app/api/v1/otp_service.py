import asyncpg
from fastapi import APIRouter
from fastapi.params import Depends

from app.database import get_database_pool
from app.exceptions.database_error_module import handle_database_exceptions
from app.exceptions.http_error_module import handle_http_exceptions

router: APIRouter = APIRouter()


@router.get("/otp")
@handle_database_exceptions
@handle_http_exceptions
async def get_otp(
        tenant_id: str,
        user_email: str,
        db: asyncpg.Connection = Depends(
            get_database_pool
        )
):
    pass