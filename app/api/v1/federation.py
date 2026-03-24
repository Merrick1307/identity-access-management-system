from fastapi import APIRouter, Depends, HTTPException, status
import asyncpg

from app.audit_logs import AuditLogger, background_logger
from app.core.jwt_utils import verify_and_return_jwt_payload, VerifiedTokenData
from app.core.responses import success_response, created_response, no_content_response
from app.database import get_database_pool
from app.models.federation import IdentityProviderCreate, IdentityProviderUpdate
from app.services import federation_service

router = APIRouter(prefix="/federation", tags=["federation"])


def _require_admin(user: VerifiedTokenData):
    if user.role not in ("admin", "superadmin", "root"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")


def _serialize_provider(provider: dict) -> dict:
    return {
        "id": provider["id"],
        "tenant_id": provider["tenant_id"],
        "name": provider["name"],
        "protocol": provider["protocol"],
        "issuer_url": provider["issuer_url"],
        "client_id": provider.get("client_id"),
        "discovery_url": provider.get("discovery_url"),
        "authorization_endpoint": provider.get("authorization_endpoint"),
        "token_endpoint": provider.get("token_endpoint"),
        "userinfo_endpoint": provider.get("userinfo_endpoint"),
        "jwks_uri": provider.get("jwks_uri"),
        "enabled": provider.get("enabled", True),
        "auto_link": provider.get("auto_link", True),
        "authorization_scopes": provider.get("authorization_scopes") or "openid profile email",
        "token_endpoint_auth_method": provider.get("token_endpoint_auth_method") or "client_secret_post",
        "claims_source": provider.get("claims_source") or "auto",
        "link_by_email_verified_only": provider.get("link_by_email_verified_only", True),
        "default_role": provider.get("default_role") or "member",
        "created_at": provider.get("created_at").isoformat() if provider.get("created_at") else None,
        "last_modified": provider.get("last_modified").isoformat() if provider.get("last_modified") else None,
    }


@router.get("/providers")
async def list_identity_providers(
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
):
    providers = await federation_service.list_identity_providers(db, user.tenant_id)
    return success_response([_serialize_provider(p) for p in providers], "Identity providers retrieved")


@router.post("/providers")
async def create_identity_provider(
    payload: IdentityProviderCreate,
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    logger: AuditLogger = Depends(background_logger),
):
    _require_admin(user)
    provider = await federation_service.create_identity_provider(db, user.tenant_id, payload.model_dump())
    logger.audit(resource="/federation/providers", action="identity_provider_created", user_id=user.user_id, tenant_id=user.tenant_id, decision=provider["issuer_url"])
    return created_response(_serialize_provider(provider), "Identity provider created")


@router.get("/providers/{provider_id}")
async def get_identity_provider(
    provider_id: str,
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
):
    provider = await federation_service.get_identity_provider(db, user.tenant_id, provider_id)
    if not provider:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity provider not found")
    return success_response(_serialize_provider(provider))


@router.patch("/providers/{provider_id}")
async def update_identity_provider(
    provider_id: str,
    payload: IdentityProviderUpdate,
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    logger: AuditLogger = Depends(background_logger),
):
    _require_admin(user)
    provider = await federation_service.update_identity_provider(db, user.tenant_id, provider_id, payload.model_dump(exclude_none=True))
    if not provider:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity provider not found")
    logger.audit(resource=f"/federation/providers/{provider_id}", action="identity_provider_updated", user_id=user.user_id, tenant_id=user.tenant_id, decision=provider["issuer_url"])
    return success_response(_serialize_provider(provider), "Identity provider updated")


@router.delete("/providers/{provider_id}")
async def delete_identity_provider(
    provider_id: str,
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
    logger: AuditLogger = Depends(background_logger),
):
    _require_admin(user)
    deleted = await federation_service.delete_identity_provider(db, user.tenant_id, provider_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity provider not found")
    logger.audit(resource=f"/federation/providers/{provider_id}", action="identity_provider_deleted", user_id=user.user_id, tenant_id=user.tenant_id, decision="deleted")
    return no_content_response()


@router.get("/providers/{provider_id}/links")
async def list_provider_links(
    provider_id: str,
    db: asyncpg.Connection = Depends(get_database_pool),
    user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
):
    _require_admin(user)
    links = await federation_service.list_federated_links_for_provider(db, user.tenant_id, provider_id)
    serialized = [
        {
            **link,
            "created_at": link.get("created_at").isoformat() if link.get("created_at") else None,
        }
        for link in links
    ]
    return success_response(serialized, "Federated links retrieved")
