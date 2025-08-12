import asyncpg
import bcrypt
from email_validator import validate_email
from fastapi import HTTPException, status
from pydantic import EmailStr

from app.core.queries import fetch_user, fetch_user_policy


async def user_login(
        db: asyncpg.Connection,
        email: str,
        tenant_id: str,
        password: str
):
    try:
        normalized_email = validate_email(
            email, check_deliverability=True
        )

        user_data = await db.fetchval(fetch_user, normalized_email, tenant_id)

        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Invalid email or password"
            )

        hashed_password: str = user_data.get("password")

        valid_password = bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))
        if not valid_password:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Invalid email or password"
            )

        tenant_policy = await db.fetchrow(fetch_user_policy, normalized_email, tenant_id)

        payload = {
            "email": normalized_email,
            "tenant_id": tenant_id,
        }