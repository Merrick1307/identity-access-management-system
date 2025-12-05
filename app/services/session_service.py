import asyncio
import json
from datetime import datetime, timezone, timedelta
from typing import Optional, List

import asyncpg
from rbloom import Bloom

from app.audit_logs import AuditLogger


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
        json.dumps(device_info) if device_info else None,
        ip_address,
        expires_at
    )


async def get_active_sessions(
    db: asyncpg.Connection,
    user_id: str,
    tenant_id: str
) -> List[dict]:
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
        {
            "jti": row["jti"],
            "device_info": json.loads(row["device_info"]) if row["device_info"] else None,
            "ip_address": str(row["ip_address"]) if row["ip_address"] else None,
            "created_at": row["created_at"].isoformat(),
            "expires_at": row["expires_at"].isoformat()
        }
        for row in rows
    ]


async def revoke_session(
    db: asyncpg.Connection,
    bloom: Bloom,
    jti: str,
    user_id: str,
    tenant_id: str,
    reason: str = "logout"
) -> bool:
    result = await db.execute(
        """
        UPDATE user_sessions 
        SET revoked_at = NOW(), revoked_reason = $4
        WHERE jti = $1 AND user_id = $2 AND tenant_id = $3 AND revoked_at IS NULL
        """,
        jti, user_id, tenant_id, reason
    )
    
    if result != "UPDATE 0":
        await asyncio.to_thread(bloom.add, jti)
        return True
    return False


async def revoke_all_sessions(
    db: asyncpg.Connection,
    bloom: Bloom,
    user_id: str,
    tenant_id: str,
    logger: AuditLogger,
    reason: str = "bulk_logout",
    exclude_jti: Optional[str] = None
) -> int:
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
    
    for jti in jtis:
        await asyncio.to_thread(bloom.add, jti)
    
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
