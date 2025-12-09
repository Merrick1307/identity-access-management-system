"""
Tenant Settings Service

Manages tenant configuration including MFA settings, token TTL, password policies, etc.
"""
from typing import Optional
from datetime import datetime, timezone

import asyncpg
import orjson

from app.audit_logs import AuditLogger


# Default tenant settings schema
DEFAULT_SETTINGS = {
    "mfa": {
        "enabled": False,
        "required_for_admins": False,
        "methods": ["totp", "email"]
    },
    "tokens": {
        "access_token_ttl": 3600,  # 1 hour
        "refresh_token_ttl": 604800,  # 7 days
        "id_token_ttl": 3600
    },
    "password_policy": {
        "min_length": 8,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numbers": True,
        "require_special": False,
        "max_age_days": 90,
        "prevent_reuse_count": 5
    },
    "session": {
        "max_concurrent_sessions": 5,
        "idle_timeout_minutes": 30,
        "absolute_timeout_hours": 24
    },
    "security": {
        "lockout_threshold": 5,
        "lockout_duration_minutes": 15,
        "require_email_verification": True
    },
    "branding": {
        "logo_url": None,
        "primary_color": "#3B82F6",
        "company_name": None
    }
}


async def get_tenant(
    db: asyncpg.Connection,
    tenant_id: str
) -> Optional[dict]:
    """Get tenant by ID."""
    row = await db.fetchrow(
        """
        SELECT id, name, domain, root, settings, is_active, created_at
        FROM tenants
        WHERE id = $1
        """,
        tenant_id
    )
    if not row:
        return None
    
    settings = row['settings']
    if isinstance(settings, str):
        settings = orjson.loads(settings)
    
    return {
        "id": row['id'],
        "name": row['name'],
        "domain": row['domain'],
        "root": row['root'],
        "settings": settings or DEFAULT_SETTINGS,
        "is_active": row['is_active'],
        "created_at": row['created_at'].isoformat() if row['created_at'] else None
    }


async def get_tenant_settings(
    db: asyncpg.Connection,
    tenant_id: str
) -> dict:
    """Get tenant settings, returning defaults if not set."""
    row = await db.fetchrow(
        "SELECT settings FROM tenants WHERE id = $1",
        tenant_id
    )
    if not row or not row['settings']:
        return DEFAULT_SETTINGS
    
    settings = row['settings']
    if isinstance(settings, str):
        settings = orjson.loads(settings)
    
    # Merge with defaults to ensure all keys exist
    return _merge_settings(DEFAULT_SETTINGS, settings)


def _merge_settings(defaults: dict, overrides: dict) -> dict:
    """Deep merge settings with defaults."""
    result = defaults.copy()
    for key, value in overrides.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _merge_settings(result[key], value)
        else:
            result[key] = value
    return result


async def update_tenant_settings(
    db: asyncpg.Connection,
    tenant_id: str,
    settings: dict,
    logger: AuditLogger
) -> dict:
    """Update tenant settings (partial update supported)."""
    # Get current settings
    current = await get_tenant_settings(db, tenant_id)
    
    # Merge new settings
    updated = _merge_settings(current, settings)
    
    # Save to database
    settings_json = orjson.dumps(updated).decode()
    await db.execute(
        """
        UPDATE tenants 
        SET settings = $2::jsonb
        WHERE id = $1
        """,
        tenant_id, settings_json
    )
    
    logger.info(
        f"Tenant settings updated",
        tenant_id=tenant_id,
        updated_keys=list(settings.keys())
    )
    
    return updated


async def update_mfa_settings(
    db: asyncpg.Connection,
    tenant_id: str,
    enabled: bool,
    required_for_admins: bool = False,
    methods: list = None,
    logger: AuditLogger = None
) -> dict:
    """Update MFA-specific settings."""
    mfa_settings = {
        "mfa": {
            "enabled": enabled,
            "required_for_admins": required_for_admins,
            "methods": methods or ["totp", "email"]
        }
    }
    return await update_tenant_settings(db, tenant_id, mfa_settings, logger)


async def update_token_settings(
    db: asyncpg.Connection,
    tenant_id: str,
    access_token_ttl: int = None,
    refresh_token_ttl: int = None,
    id_token_ttl: int = None,
    logger: AuditLogger = None
) -> dict:
    """Update token TTL settings."""
    current = await get_tenant_settings(db, tenant_id)
    token_settings = current.get("tokens", {})
    
    if access_token_ttl is not None:
        token_settings["access_token_ttl"] = access_token_ttl
    if refresh_token_ttl is not None:
        token_settings["refresh_token_ttl"] = refresh_token_ttl
    if id_token_ttl is not None:
        token_settings["id_token_ttl"] = id_token_ttl
    
    return await update_tenant_settings(db, tenant_id, {"tokens": token_settings}, logger)


async def update_password_policy(
    db: asyncpg.Connection,
    tenant_id: str,
    policy: dict,
    logger: AuditLogger
) -> dict:
    """Update password policy settings."""
    return await update_tenant_settings(db, tenant_id, {"password_policy": policy}, logger)


async def update_branding(
    db: asyncpg.Connection,
    tenant_id: str,
    branding: dict,
    logger: AuditLogger
) -> dict:
    """Update branding settings."""
    return await update_tenant_settings(db, tenant_id, {"branding": branding}, logger)


async def list_tenants(
    db: asyncpg.Connection,
    page: int = 1,
    page_size: int = 20,
    search: str = None
) -> tuple[list, int]:
    """List all tenants with pagination (superadmin only)."""
    offset = (page - 1) * page_size
    
    if search:
        count_query = """
            SELECT COUNT(*) FROM tenants 
            WHERE name ILIKE $1 OR domain ILIKE $1
        """
        query = """
            SELECT id, name, domain, root, settings, is_active, created_at
            FROM tenants
            WHERE name ILIKE $1 OR domain ILIKE $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
        """
        search_pattern = f"%{search}%"
        total = await db.fetchval(count_query, search_pattern)
        rows = await db.fetch(query, search_pattern, page_size, offset)
    else:
        total = await db.fetchval("SELECT COUNT(*) FROM tenants")
        rows = await db.fetch(
            """
            SELECT id, name, domain, root, settings, is_active, created_at
            FROM tenants
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            """,
            page_size, offset
        )
    
    tenants = []
    for row in rows:
        settings = row['settings']
        if isinstance(settings, str):
            settings = orjson.loads(settings)
        tenants.append({
            "id": row['id'],
            "name": row['name'],
            "domain": row['domain'],
            "root": row['root'],
            "settings": settings,
            "is_active": row['is_active'],
            "created_at": row['created_at'].isoformat() if row['created_at'] else None
        })
    
    return tenants, total


async def deactivate_tenant(
    db: asyncpg.Connection,
    tenant_id: str,
    logger: AuditLogger
) -> bool:
    """Deactivate a tenant."""
    await db.execute(
        "UPDATE tenants SET is_active = FALSE WHERE id = $1",
        tenant_id
    )
    logger.warning(f"Tenant {tenant_id} deactivated")
    return True


async def activate_tenant(
    db: asyncpg.Connection,
    tenant_id: str,
    logger: AuditLogger
) -> bool:
    """Activate a tenant."""
    await db.execute(
        "UPDATE tenants SET is_active = TRUE WHERE id = $1",
        tenant_id
    )
    logger.info(f"Tenant {tenant_id} activated")
    return True
