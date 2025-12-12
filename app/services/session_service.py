from datetime import datetime

import orjson
from typing import Optional, List, TYPE_CHECKING

import asyncpg

from app.audit_logs import AuditLogger
from app.models.responses import SessionInfo, TenantSessionInfo

if TYPE_CHECKING:
    from app.core.token_revocation import TokenRevocationManager


async def create_session(
    db: asyncpg.Connection,
    jti: str,
    user_id: str,
    tenant_id: str,
    expires_at: datetime,
    ip_address: Optional[str] = None,
    device_info: Optional[dict] = None
) -> None:
    await db.execute(
        """
        INSERT INTO user_sessions (jti, user_id, tenant_id, device_info, ip_address, expires_at)
        VALUES ($1, $2, $3, $4, $5::inet, $6)
        ON CONFLICT (jti) DO NOTHING
        """,
        jti, user_id, tenant_id,
        orjson.dumps(device_info).decode() if device_info else None,
        ip_address,
        expires_at
    )


async def get_active_sessions(
    db: asyncpg.Connection,
    user_id: str,
    tenant_id: str
) -> List[SessionInfo]:
    rows = await db.fetch(
        """
        SELECT jti, device_info, ip_address, created_at, expires_at
        FROM user_sessions
        WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
        AND expires_at > NOW()
        ORDER BY created_at DESC
        """,
        user_id, tenant_id
    )
    return [
        SessionInfo(
            jti=row["jti"],
            device_info=orjson.loads(row["device_info"]) if row["device_info"] else None,
            ip_address=str(row["ip_address"]) if row["ip_address"] else None,
            created_at=row["created_at"].isoformat(),
            expires_at=row["expires_at"].isoformat()
        )
        for row in rows
    ]


async def revoke_session(
    db: asyncpg.Connection,
    revocation_manager: "TokenRevocationManager",
    jti: str,
    user_id: str,
    tenant_id: str,
    reason: str = "logout"
) -> bool:
    """Revoke a single session and broadcast to all workers via Redis Stream."""
    result = await db.execute(
        """
        UPDATE user_sessions 
        SET revoked_at = NOW(), revoked_reason = $4
        WHERE jti = $1 AND user_id = $2 AND tenant_id = $3 AND revoked_at IS NULL
        """,
        jti, user_id, tenant_id, reason
    )
    
    if result != "UPDATE 0":
        # Publish to Redis Stream - all workers will add to their bloom filters
        await revocation_manager.revoke_token(jti, user_id, tenant_id, reason)
        return True
    return False


async def revoke_all_sessions(
    db: asyncpg.Connection,
    revocation_manager: "TokenRevocationManager",
    user_id: str,
    tenant_id: str,
    logger: AuditLogger,
    reason: str = "bulk_logout",
    exclude_jti: Optional[str] = None
) -> int:
    """Revoke all sessions for a user and broadcast to all workers."""
    if exclude_jti:
        rows = await db.fetch(
            """
            SELECT jti FROM user_sessions
            WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
            AND jti != $3
            """,
            user_id, tenant_id, exclude_jti
        )
    else:
        rows = await db.fetch(
            """
            SELECT jti FROM user_sessions
            WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
            """,
            user_id, tenant_id
        )
    
    if not rows:
        return 0
    
    jtis = [row["jti"] for row in rows]
    
    # Publish all revocations to Redis Stream - all workers will sync
    await revocation_manager.revoke_user_tokens(user_id, tenant_id, jtis, reason)
    
    if exclude_jti:
        await db.execute(
            """
            UPDATE user_sessions 
            SET revoked_at = NOW(), revoked_reason = $3
            WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
            AND jti != $4
            """,
            user_id, tenant_id, reason, exclude_jti
        )
    else:
        await db.execute(
            """
            UPDATE user_sessions 
            SET revoked_at = NOW(), revoked_reason = $3
            WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
            """,
            user_id, tenant_id, reason
        )
    
    logger.audit(
        action="bulk_logout",
        user_id=user_id,
        tenant_id=tenant_id,
        resource="sessions",
        decision=f"Revoked {len(jtis)} sessions"
    )
    
    return len(jtis)


async def cleanup_expired_sessions(db: asyncpg.Connection) -> int:
    result = await db.execute(
        """
        DELETE FROM user_sessions 
        WHERE expires_at < NOW() - INTERVAL '7 days'
        """
    )
    count = int(result.split()[-1]) if result.startswith("DELETE") else 0
    return count


async def get_all_tenant_sessions(
    db: asyncpg.Connection,
    tenant_id: str,
    include_expired: bool = False
) -> List[TenantSessionInfo]:
    """Get all sessions for a tenant (admin view)."""
    if include_expired:
        query = """
            SELECT s.jti, s.user_id, u.email as user_email, s.device_info, 
                   s.ip_address, s.created_at, s.expires_at, s.revoked_at,
                   CASE 
                       WHEN s.revoked_at IS NOT NULL THEN 'revoked'
                       WHEN s.expires_at < NOW() THEN 'expired'
                       ELSE 'active'
                   END as status
            FROM user_sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.tenant_id = $1
            ORDER BY s.created_at DESC
            LIMIT 500
        """
    else:
        query = """
            SELECT s.jti, s.user_id, u.email as user_email, s.device_info, 
                   s.ip_address, s.created_at, s.expires_at,
                   'active' as status
            FROM user_sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.tenant_id = $1 AND s.revoked_at IS NULL AND s.expires_at > NOW()
            ORDER BY s.created_at DESC
            LIMIT 500
        """
    
    rows = await db.fetch(query, tenant_id)
    return [
        TenantSessionInfo(
            jti=row["jti"],
            user_id=str(row["user_id"]),
            user_email=row["user_email"],
            device_info=orjson.loads(row["device_info"]) if row["device_info"] else None,
            ip_address=str(row["ip_address"]) if row["ip_address"] else None,
            created_at=row["created_at"].isoformat(),
            expires_at=row["expires_at"].isoformat(),
            status=row["status"]
        )
        for row in rows
    ]


async def admin_revoke_session(
    db: asyncpg.Connection,
    revocation_manager: "TokenRevocationManager",
    jti: str,
    tenant_id: str,
    reason: str = "admin_revoke"
) -> bool:
    """Admin revoke a session (no user_id check - tenant admin can revoke any session)."""
    row = await db.fetchrow(
        "SELECT user_id FROM user_sessions WHERE jti = $1 AND tenant_id = $2",
        jti, tenant_id
    )
    if not row:
        return False
    
    user_id = str(row["user_id"])
    
    result = await db.execute(
        """
        UPDATE user_sessions 
        SET revoked_at = NOW(), revoked_reason = $3
        WHERE jti = $1 AND tenant_id = $2 AND revoked_at IS NULL
        """,
        jti, tenant_id, reason
    )
    
    if result != "UPDATE 0":
        await revocation_manager.revoke_token(jti, user_id, tenant_id, reason)
        return True
    return False


async def admin_bulk_revoke_sessions(
    db: asyncpg.Connection,
    revocation_manager: "TokenRevocationManager",
    jtis: List[str],
    tenant_id: str,
    logger: AuditLogger,
    reason: str = "admin_bulk_revoke"
) -> int:
    """Admin bulk revoke multiple sessions."""
    if not jtis:
        return 0
    
    # Get user_ids for these sessions
    rows = await db.fetch(
        """
        SELECT jti, user_id FROM user_sessions 
        WHERE jti = ANY($1) AND tenant_id = $2 AND revoked_at IS NULL
        """,
        jtis, tenant_id
    )
    
    if not rows:
        return 0
    
    # Revoke in database
    await db.execute(
        """
        UPDATE user_sessions 
        SET revoked_at = NOW(), revoked_reason = $3
        WHERE jti = ANY($1) AND tenant_id = $2 AND revoked_at IS NULL
        """,
        jtis, tenant_id, reason
    )
    
    # Publish revocations grouped by user
    user_jtis: dict[str, list[str]] = {}
    for row in rows:
        uid = str(row["user_id"])
        if uid not in user_jtis:
            user_jtis[uid] = []
        user_jtis[uid].append(row["jti"])
    
    for user_id, user_jti_list in user_jtis.items():
        await revocation_manager.revoke_user_tokens(user_id, tenant_id, user_jti_list, reason)
    
    logger.audit(
        action="admin_bulk_revoke",
        tenant_id=tenant_id,
        resource="sessions",
        decision=f"Revoked {len(rows)} sessions"
    )
    
    return len(rows)
