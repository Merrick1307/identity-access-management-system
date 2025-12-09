"""
User management endpoints for tenant admins.
"""
from typing import Optional

import asyncpg
from fastapi import APIRouter, Depends, Query

from app.audit_logs import AuditLogger, background_logger
from app.core.jwt_utils import verify_and_return_jwt_payload, VerifiedTokenData
from app.core.responses import success_response, OrjsonResponse
from app.database import get_database_pool
from app.exceptions.database_error_module import handle_database_exceptions
from app.exceptions.http_error_module import handle_http_exceptions

router: APIRouter = APIRouter()


@router.get("/")
@handle_http_exceptions
@handle_database_exceptions
async def list_tenant_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    search: Optional[str] = Query(None, description="Search by email or name"),
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    logger: AuditLogger = Depends(background_logger)
) -> OrjsonResponse:
    """
    List all users in the current tenant.
    Used for dropdowns and user selection in admin UI.
    """
    offset = (page - 1) * page_size
    
    # Count query
    if search:
        count_query = """
            SELECT COUNT(*) FROM users 
            WHERE (email ILIKE $1 OR first_name ILIKE $1 OR last_name ILIKE $1)
        """
        total = await db.fetchval(count_query,f"%{search}%")
        
        query = """
            SELECT id, email, first_name, last_name, role, is_active, created_at
            FROM users
            WHERE (email ILIKE $1 OR first_name ILIKE $1 OR last_name ILIKE $1)
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
        """
        rows = await db.fetch(query,f"%{search}%", page_size, offset)
    else:
        count_query = "SELECT COUNT(*) FROM users"
        total = await db.fetchval(count_query)
        
        query = """
            SELECT id, email, first_name, last_name, role, is_active, created_at
            FROM users
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
        """
        rows = await db.fetch(query, page_size, offset)
    
    users = [
        {
            "id": row["id"],
            "email": row["email"],
            "first_name": row["first_name"],
            "last_name": row["last_name"],
            "full_name": f"{row['first_name']} {row['last_name']}",
            "role": row["role"],
            "is_active": row["is_active"],
            "created_at": row["created_at"].isoformat() if row["created_at"] else None
        }
        for row in rows
    ]
    
    logger.info(f"Listed {len(users)} users for tenant {user.tenant_id}")
    
    return success_response(
        data={
            "users": users,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total_items": total,
                "total_pages": (total + page_size - 1) // page_size if page_size > 0 else 0
            }
        },
        message=f"Found {total} users"
    )


@router.get("/{user_id}")
@handle_http_exceptions
@handle_database_exceptions
async def get_user_by_id(
    user_id: str,
    db: asyncpg.Connection = Depends(get_database_pool),
    current_user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
) -> OrjsonResponse:
    """Get a specific user by ID within the tenant."""
    query = """
        SELECT id, email, first_name, last_name, role, is_active, 
               email_verified, created_at, last_login
        FROM users
        WHERE id = $1
    """
    row = await db.fetchrow(query, user_id)
    
    if not row:
        return success_response(data=None, message="User not found")
    
    return success_response(
        data={
            "id": row["id"],
            "email": row["email"],
            "first_name": row["first_name"],
            "last_name": row["last_name"],
            "full_name": f"{row['first_name']} {row['last_name']}",
            "role": row["role"],
            "is_active": row["is_active"],
            "email_verified": row["email_verified"],
            "created_at": row["created_at"].isoformat() if row["created_at"] else None,
            "last_login": row["last_login"].isoformat() if row["last_login"] else None
        }
    )
