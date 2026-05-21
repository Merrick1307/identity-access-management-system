"""
OIDC Client Management Endpoints

Allows tenant admins to register and manage OAuth2/OIDC client applications.
"""
import secrets
from typing import List, Optional

import asyncpg
import bcrypt
from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel

from app.audit_logs import AuditLogger, background_logger
from app.core.jwt_utils import decode_jwt_token, verify_and_return_jwt_payload, VerifiedTokenData
from app.core.responses import (
    OrjsonResponse, success_response, created_response, error_response
)
from app.database import get_database_pool
from app.database.queries import QUERIES


router = APIRouter()


class ClientCreateRequest(BaseModel):
    name: str
    redirect_uris: List[str]
    scopes: List[str] = ["openid", "profile", "email"]


class ClientUpdateRequest(BaseModel):
    name: Optional[str] = None
    redirect_uris: Optional[List[str]] = None
    scopes: Optional[List[str]] = None


def generate_client_id() -> str:
    """Generate a unique client ID."""
    return f"client_{secrets.token_hex(16)}"


def generate_client_secret() -> str:
    """Generate a secure client secret."""
    return secrets.token_urlsafe(32)


def hash_client_secret(secret: str) -> str:
    """Hash client secret for storage."""
    return bcrypt.hashpw(secret.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


async def get_auth_context(request: Request) -> Optional[dict]:
    """Extract and validate authentication from request."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    
    token = auth_header[7:]
    try:
        payload = decode_jwt_token(token, verify_aud=False)
        return {
            "user_id": payload.get("user_id"),
            "tenant_id": payload.get("tenant_id"),
            "role": payload.get("role")
        }
    except Exception:
        return None


@router.post("/clients", response_class=OrjsonResponse)
async def register_client(
    client_data: ClientCreateRequest,
    auth: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    db: asyncpg.Connection = Depends(get_database_pool),
    logger: AuditLogger = Depends(background_logger)
):
    """
    Register a new OIDC client application.
    
    Requires tenant admin authentication.
    Returns client_id and client_secret (secret shown only once).
    """
    tenant_id = auth.tenant_id
    user_id = auth.user_id
    
    client_id = generate_client_id()
    client_secret = generate_client_secret()
    hashed_secret = hash_client_secret(client_secret)
    
    await db.execute(
        QUERIES["oidc_client_insert"],
        client_id,
        tenant_id,
        hashed_secret,
        client_data.name,
        client_data.redirect_uris,
        client_data.scopes
    )
    
    logger.audit(
        resource="/oidc/clients",
        action="client_registered",
        user_id=user_id,
        tenant_id=tenant_id,
        decision=f"Client '{client_data.name}' registered"
    )
    
    return created_response(
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "name": client_data.name,
            "redirect_uris": client_data.redirect_uris,
            "scopes": client_data.scopes,
            "warning": "Store the client_secret securely. It cannot be retrieved again."
        },
        message="Client registered successfully"
    )


@router.get("/clients", response_class=OrjsonResponse)
async def list_clients(
    auth: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    db: asyncpg.Connection = Depends(get_database_pool),
    logger: AuditLogger = Depends(background_logger)
):
    """List all OIDC clients for the tenant."""
    tenant_id = auth.tenant_id
    
    clients = await db.fetch(QUERIES["oidc_client_list_by_tenant"], tenant_id)
    
    return success_response(
        data=[
            {
                "client_id": c["id"],
                "name": c["name"],
                "redirect_uris": c["redirect_uris"],
                "scopes": c["scopes"],
                "is_active": c["is_active"],
                "created_at": c["created_at"].isoformat() if c["created_at"] else None,
                "last_modified": c["last_modified"].isoformat() if c["last_modified"] else None
            }
            for c in clients
        ],
        message=f"Found {len(clients)} clients"
    )


@router.get("/clients/{client_id}", response_class=OrjsonResponse)
async def get_client(
    client_id: str,
    auth: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    db: asyncpg.Connection = Depends(get_database_pool)
):
    """Get details of a specific client."""
    tenant_id = auth.tenant_id
    
    client = await db.fetchrow(QUERIES["oidc_client_get_by_id"], client_id, tenant_id)
    
    if not client:
        return error_response("not_found", "Client not found", status.HTTP_404_NOT_FOUND)
    
    return success_response(
        data={
            "client_id": client["id"],
            "name": client["name"],
            "redirect_uris": client["redirect_uris"],
            "scopes": client["scopes"],
            "is_active": client["is_active"],
            "created_at": client["created_at"].isoformat() if client["created_at"] else None,
            "last_modified": client["last_modified"].isoformat() if client["last_modified"] else None
        }
    )


@router.patch("/clients/{client_id}", response_class=OrjsonResponse)
async def update_client(
    client_id: str,
    updates: ClientUpdateRequest,
    auth: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    db: asyncpg.Connection = Depends(get_database_pool),
    logger: AuditLogger = Depends(background_logger)
):
    """Update client configuration."""
    tenant_id = auth.tenant_id
    user_id = auth.user_id
    
    existing = await db.fetchrow(QUERIES["oidc_client_get_by_id"], client_id, tenant_id)
    if not existing:
        return error_response("not_found", "Client not found", status.HTTP_404_NOT_FOUND)
    
    name = updates.name if updates.name else existing["name"]
    redirect_uris = updates.redirect_uris if updates.redirect_uris else existing["redirect_uris"]
    scopes = updates.scopes if updates.scopes else existing["scopes"]
    
    await db.execute(
        QUERIES["oidc_client_update"],
        client_id,
        tenant_id,
        name,
        redirect_uris,
        scopes
    )
    
    logger.audit(
        resource=f"/oidc/clients/{client_id}",
        action="client_updated",
        user_id=user_id,
        tenant_id=tenant_id,
        decision="Client configuration updated"
    )
    
    return success_response(
        data={
            "client_id": client_id,
            "name": name,
            "redirect_uris": redirect_uris,
            "scopes": scopes
        },
        message="Client updated successfully"
    )


@router.post("/clients/{client_id}/rotate-secret", response_class=OrjsonResponse)
async def rotate_client_secret(
    client_id: str,
    auth: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    db: asyncpg.Connection = Depends(get_database_pool),
    logger: AuditLogger = Depends(background_logger)
):
    """
    Rotate client secret.
    
    Generates a new client_secret. The old secret is immediately invalidated.
    """
    tenant_id = auth.tenant_id
    user_id = auth.user_id
    
    existing = await db.fetchrow(QUERIES["oidc_client_get_by_id"], client_id, tenant_id)
    if not existing:
        return error_response("not_found", "Client not found", status.HTTP_404_NOT_FOUND)
    
    new_secret = generate_client_secret()
    hashed_secret = hash_client_secret(new_secret)
    
    await db.execute(
        QUERIES["oidc_client_rotate_secret"],
        client_id,
        tenant_id,
        hashed_secret
    )
    
    logger.audit(
        resource=f"/oidc/clients/{client_id}",
        action="client_secret_rotated",
        user_id=user_id,
        tenant_id=tenant_id,
        decision="Client secret rotated"
    )
    
    return success_response(
        data={
            "client_id": client_id,
            "client_secret": new_secret,
            "warning": "Store the new client_secret securely. It cannot be retrieved again."
        },
        message="Client secret rotated successfully"
    )


@router.delete("/clients/{client_id}", response_class=OrjsonResponse)
async def delete_client(
    client_id: str,
    auth: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    db: asyncpg.Connection = Depends(get_database_pool),
    logger: AuditLogger = Depends(background_logger)
):
    """Delete an OIDC client."""
    tenant_id = auth.tenant_id
    user_id = auth.user_id
    
    result = await db.execute(QUERIES["oidc_client_delete"], client_id, tenant_id)
    
    if result == "DELETE 0":
        return error_response("not_found", "Client not found", status.HTTP_404_NOT_FOUND)
    
    logger.audit(
        resource=f"/oidc/clients/{client_id}",
        action="client_deleted",
        user_id=user_id,
        tenant_id=tenant_id,
        decision="Client deleted"
    )
    
    return success_response(message="Client deleted successfully")
