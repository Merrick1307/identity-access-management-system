"""
Tenant Settings API Router

Endpoints for managing tenant configuration.
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request

from app.audit_logs import AuditLogger, background_logger
from app.core.jwt_utils import VerifiedTokenData, verify_and_return_jwt_payload
from app.core.responses import success_response, paginated_response, not_found_response
from app.database import get_database_pool
from app.models.tenants import TenantSettingsUpdate, MFASettings, TokenSettings, PasswordPolicy, BrandingSettings
from app.services import tenant_service

router = APIRouter(prefix="/tenants", tags=["Tenants"])


@router.get("/me")
async def get_current_tenant(
    request: Request,
    db=Depends(get_database_pool)
):
    """Get current tenant details."""
    tenant_id = request.state.user.get("tenant_id")
    tenant = await tenant_service.get_tenant(db, tenant_id)
    
    if not tenant:
        return not_found_response("Tenant")
    
    return success_response(tenant)


@router.get("/me/settings")
async def get_current_tenant_settings(
    request: Request,
    db=Depends(get_database_pool),
    user_object: VerifiedTokenData = Depends(
        verify_and_return_jwt_payload
    )
):
    """Get current tenant settings."""
    tenant_id = user_object.tenant_id
    settings = await tenant_service.get_tenant_settings(db, tenant_id)
    return success_response(settings)


@router.patch("/me/settings")
async def update_current_tenant_settings(
        request: Request,
        updates: TenantSettingsUpdate,
        db=Depends(get_database_pool),
        user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
        logger: AuditLogger = Depends(background_logger)
):
    """
    Update current tenant settings.
    
    Supports partial updates - only provided fields will be updated.
    Requires admin role.
    """
    tenant_id = user.tenant_id
    
    # Check admin permission
    if user.role not in ("admin", "superadmin", "root"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required to update settings"
        )
    
    # Build settings dict from non-None fields
    settings_update = {}
    if updates.mfa:
        settings_update["mfa"] = updates.mfa.model_dump()
    if updates.tokens:
        settings_update["tokens"] = updates.tokens.model_dump()
    if updates.password_policy:
        settings_update["password_policy"] = updates.password_policy.model_dump()
    if updates.session:
        settings_update["session"] = updates.session.model_dump()
    if updates.security:
        settings_update["security"] = updates.security.model_dump()
    if updates.branding:
        settings_update["branding"] = updates.branding.model_dump()
    
    if not settings_update:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No settings provided to update"
        )
    
    updated = await tenant_service.update_tenant_settings(
        db, tenant_id, settings_update, logger
    )
    
    return success_response(updated, "Settings updated successfully")


@router.put("/me/settings/mfa")
async def update_mfa_settings(
        request: Request,
        settings: MFASettings,
        db=Depends(get_database_pool),
        user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
        logger: AuditLogger = Depends(background_logger)
):
    """Update MFA settings."""
    tenant_id = user.tenant_id
    
    if user.role not in ("admin", "superadmin", "root"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required"
        )
    
    updated = await tenant_service.update_mfa_settings(
        db, tenant_id,
        enabled=settings.enabled,
        required_for_admins=settings.required_for_admins,
        methods=settings.methods,
        logger=logger
    )
    
    return success_response(updated["mfa"], "MFA settings updated")


@router.put("/me/settings/tokens")
async def update_token_settings(
        request: Request,
        settings: TokenSettings,
        db=Depends(get_database_pool),
        user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
        logger: AuditLogger = Depends(background_logger)
):
    """Update token TTL settings."""
    tenant_id = user.tenant_id
    
    if user.role not in ("admin", "superadmin", "root"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required"
        )
    
    updated = await tenant_service.update_token_settings(
        db, tenant_id,
        access_token_ttl=settings.access_token_ttl,
        refresh_token_ttl=settings.refresh_token_ttl,
        id_token_ttl=settings.id_token_ttl,
        logger=logger
    )
    
    return success_response(updated["tokens"], "Token settings updated")


@router.put("/me/settings/password-policy")
async def update_password_policy(
        request: Request,
        policy: PasswordPolicy,
        db=Depends(get_database_pool),
        user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
        logger: AuditLogger = Depends(background_logger)
):
    """Update password policy."""
    tenant_id = user.tenant_id
    
    if user.role not in ("admin", "superadmin", "root"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required"
        )
    
    updated = await tenant_service.update_password_policy(
        db, tenant_id, policy.model_dump(), logger
    )
    
    return success_response(updated["password_policy"], "Password policy updated")


@router.put("/me/settings/branding")
async def update_branding(
        request: Request,
        branding: BrandingSettings,
        db=Depends(get_database_pool),
        user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
        logger: AuditLogger = Depends(background_logger)
):
    """Update branding settings."""
    tenant_id = user.tenant_id
    
    if user.role not in ("admin", "superadmin", "root"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required"
        )
    
    updated = await tenant_service.update_branding(
        db, tenant_id, branding.model_dump(), logger
    )
    
    return success_response(updated["branding"], "Branding updated")


# Superadmin endpoints
@router.get("/")
async def list_tenants(
        request: Request,
        page: int = 1,
        page_size: int = 20,
        search: Optional[str] = None,
        user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
        db=Depends(get_database_pool)
):
    """List all tenants (superadmin only)."""
    if user.role not in ("superadmin", "root"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superadmin role required"
        )
    
    tenants, total = await tenant_service.list_tenants(db, page, page_size, search)
    return paginated_response(tenants, page, page_size, total)


@router.get("/{tenant_id}")
async def get_tenant(
        tenant_id: str,
        request: Request,
        user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
        db=Depends(get_database_pool)
):
    """Get tenant by ID (superadmin only)."""
    if user.role not in ("superadmin", "root"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superadmin role required"
        )
    
    tenant = await tenant_service.get_tenant(db, tenant_id)
    if not tenant:
        return not_found_response("Tenant")
    
    return success_response(tenant)


@router.post("/{tenant_id}/deactivate")
async def deactivate_tenant(
        tenant_id: str,
        request: Request,
        db=Depends(get_database_pool),
        user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
        logger: AuditLogger = Depends(background_logger)
):
    """Deactivate a tenant (superadmin only)."""
    if user.role not in ("superadmin", "root"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superadmin role required"
        )
    
    await tenant_service.deactivate_tenant(db, tenant_id, logger)
    return success_response(None, "Tenant deactivated")


@router.post("/{tenant_id}/activate")
async def activate_tenant(
        tenant_id: str,
        request: Request,
        db=Depends(get_database_pool),
        user: VerifiedTokenData = Depends(verify_and_return_jwt_payload),
        logger: AuditLogger = Depends(background_logger)
):
    """Activate a tenant (superadmin only)."""
    if user.role not in ("superadmin", "root"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superadmin role required"
        )
    
    await tenant_service.activate_tenant(db, tenant_id, logger)
    return success_response(None, "Tenant activated")
