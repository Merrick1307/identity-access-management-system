import json
from typing import List, Optional
from datetime import datetime, timezone

import asyncpg
from fastapi import HTTPException, status

from app.audit_logs import AuditLogger
from app.models.policy import PolicyCreate, PolicyUpdate, PolicyResponse, AssignPolicyRequest


async def get_user_policies(
    db: asyncpg.Connection,
    tenant_id: str,
    user_id: str,
    logger: AuditLogger
) -> List[PolicyResponse]:
    query = """
        SELECT policy_id, user_id, tenant_id, policy, created_at, last_modified
        FROM user_policies
        WHERE tenant_id = $1 AND user_id = $2
    """
    rows = await db.fetch(query, tenant_id, user_id)
    
    policies = []
    for row in rows:
        policy_data = json.loads(row['policy']) if isinstance(row['policy'], str) else row['policy']
        policies.append(PolicyResponse(
            policy_id=row['policy_id'],
            user_id=row['user_id'],
            tenant_id=row['tenant_id'],
            resource=policy_data.get('resource', ''),
            actions=policy_data.get('actions', []),
            conditions=policy_data.get('conditions'),
            created_at=row['created_at'].isoformat() if row['created_at'] else None,
            last_modified=row['last_modified'].isoformat() if row['last_modified'] else None
        ))
    
    logger.info(f"Retrieved {len(policies)} policies for user {user_id}")
    return policies


async def get_policy_by_id(
    db: asyncpg.Connection,
    tenant_id: str,
    user_id: str,
    policy_id: str,
    logger: AuditLogger
) -> Optional[PolicyResponse]:
    query = """
        SELECT policy_id, user_id, tenant_id, policy, created_at, last_modified
        FROM user_policies
        WHERE tenant_id = $1 AND user_id = $2 AND policy_id = $3
    """
    row = await db.fetchrow(query, tenant_id, user_id, policy_id)
    
    if not row:
        return None
    
    policy_data = json.loads(row['policy']) if isinstance(row['policy'], str) else row['policy']
    return PolicyResponse(
        policy_id=row['policy_id'],
        user_id=row['user_id'],
        tenant_id=row['tenant_id'],
        resource=policy_data.get('resource', ''),
        actions=policy_data.get('actions', []),
        conditions=policy_data.get('conditions'),
        created_at=row['created_at'].isoformat() if row['created_at'] else None,
        last_modified=row['last_modified'].isoformat() if row['last_modified'] else None
    )


async def create_policy(
    db: asyncpg.Connection,
    tenant_id: str,
    user_id: str,
    policy: PolicyCreate,
    logger: AuditLogger
) -> PolicyResponse:
    existing = await db.fetchrow(
        "SELECT 1 FROM user_policies WHERE tenant_id = $1 AND user_id = $2 AND policy_id = $3",
        tenant_id, user_id, policy.policy_id
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Policy '{policy.policy_id}' already exists for this user"
        )
    
    policy_json = json.dumps({
        "resource": policy.resource,
        "actions": policy.actions,
        "conditions": policy.conditions or {}
    })
    
    await db.execute(
        """
        INSERT INTO user_policies (tenant_id, user_id, policy_id, policy)
        VALUES ($1, $2, $3, $4)
        """,
        tenant_id, user_id, policy.policy_id, policy_json
    )
    
    logger.audit(
        action="policy_create",
        user_id=user_id,
        tenant_id=tenant_id,
        resource=policy.resource,
        decision="Policy Created",
        policy_id=policy.policy_id
    )
    
    return PolicyResponse(
        policy_id=policy.policy_id,
        user_id=user_id,
        tenant_id=tenant_id,
        resource=policy.resource,
        actions=policy.actions,
        conditions=policy.conditions,
        created_at=datetime.now(timezone.utc).isoformat()
    )


async def update_policy(
    db: asyncpg.Connection,
    tenant_id: str,
    user_id: str,
    policy_id: str,
    updates: PolicyUpdate,
    logger: AuditLogger
) -> PolicyResponse:
    existing = await get_policy_by_id(db, tenant_id, user_id, policy_id, logger)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy '{policy_id}' not found for this user"
        )
    
    new_resource = updates.resource if updates.resource is not None else existing.resource
    new_actions = updates.actions if updates.actions is not None else existing.actions
    new_conditions = updates.conditions if updates.conditions is not None else existing.conditions
    
    policy_json = json.dumps({
        "resource": new_resource,
        "actions": new_actions,
        "conditions": new_conditions or {}
    })
    
    await db.execute(
        """
        UPDATE user_policies 
        SET policy = $4, last_modified = NOW()
        WHERE tenant_id = $1 AND user_id = $2 AND policy_id = $3
        """,
        tenant_id, user_id, policy_id, policy_json
    )
    
    logger.audit(
        action="policy_update",
        user_id=user_id,
        tenant_id=tenant_id,
        resource=new_resource,
        decision="Policy Updated",
        policy_id=policy_id
    )
    
    return PolicyResponse(
        policy_id=policy_id,
        user_id=user_id,
        tenant_id=tenant_id,
        resource=new_resource,
        actions=new_actions,
        conditions=new_conditions,
        last_modified=datetime.now(timezone.utc).isoformat()
    )


async def delete_policy(
    db: asyncpg.Connection,
    tenant_id: str,
    user_id: str,
    policy_id: str,
    logger: AuditLogger
) -> bool:
    result = await db.execute(
        """
        DELETE FROM user_policies 
        WHERE tenant_id = $1 AND user_id = $2 AND policy_id = $3
        """,
        tenant_id, user_id, policy_id
    )
    
    if result == "DELETE 0":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy '{policy_id}' not found for this user"
        )
    
    await logger.force_info(
        f"Policy '{policy_id}' deleted for user {user_id} in tenant {tenant_id}"
    )
    
    logger.audit(
        action="policy_delete",
        user_id=user_id,
        tenant_id=tenant_id,
        resource=policy_id,
        decision="Policy Deleted",
        policy_id=policy_id
    )
    
    return True


async def assign_policy_to_user(
    db: asyncpg.Connection,
    tenant_id: str,
    request: AssignPolicyRequest,
    logger: AuditLogger
) -> PolicyResponse:
    target_user = await db.fetchrow(
        "SELECT id FROM users WHERE id = $1 AND tenant_id = $2",
        request.user_id, tenant_id
    )
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{request.user_id}' not found in this tenant"
        )
    
    policy = PolicyCreate(
        policy_id=request.policy_id,
        resource=request.resource,
        actions=request.actions,
        conditions=request.conditions
    )
    
    return await create_policy(db, tenant_id, request.user_id, policy, logger)


async def bulk_assign_policy(
    db: asyncpg.Connection,
    tenant_id: str,
    user_ids: List[str],
    policy_id: str,
    resource: str,
    actions: List[str],
    conditions: Optional[dict],
    logger: AuditLogger
) -> dict:
    policy_json = json.dumps({
        "resource": resource,
        "actions": actions,
        "conditions": conditions or {}
    })
    
    records = [(tenant_id, uid, policy_id, policy_json) for uid in user_ids]
    
    try:
        await db.executemany(
            """
            INSERT INTO user_policies (tenant_id, user_id, policy_id, policy)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (tenant_id, user_id, policy_id) 
            DO UPDATE SET policy = EXCLUDED.policy, last_modified = NOW()
            """,
            records
        )
    except Exception as e:
        await logger.force_error(f"Bulk policy assignment failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Bulk assignment failed: {str(e)}"
        )
    
    logger.audit(
        action="policy_bulk_assign",
        tenant_id=tenant_id,
        resource=resource,
        decision="Bulk Policy Assigned",
        policy_id=policy_id,
        user_count=len(user_ids)
    )
    
    return {
        "assigned_count": len(user_ids),
        "policy_id": policy_id,
        "user_ids": user_ids
    }


async def revoke_policy_from_user(
    db: asyncpg.Connection,
    tenant_id: str,
    user_id: str,
    policy_id: str,
    logger: AuditLogger
) -> bool:
    return await delete_policy(db, tenant_id, user_id, policy_id, logger)


async def get_all_tenant_policies(
    db: asyncpg.Connection,
    tenant_id: str,
    logger: AuditLogger,
    page: int = 1,
    page_size: int = 20
) -> dict:
    offset = (page - 1) * page_size
    
    count_query = "SELECT COUNT(*) FROM user_policies WHERE tenant_id = $1"
    total = await db.fetchval(count_query, tenant_id)
    
    query = """
        SELECT up.policy_id, up.user_id, up.tenant_id, up.policy, 
               up.created_at, up.last_modified, u.email
        FROM user_policies up
        JOIN users u ON up.user_id = u.id
        WHERE up.tenant_id = $1
        ORDER BY up.created_at DESC
        LIMIT $2 OFFSET $3
    """
    rows = await db.fetch(query, tenant_id, page_size, offset)
    
    policies = []
    for row in rows:
        policy_data = json.loads(row['policy']) if isinstance(row['policy'], str) else row['policy']
        policies.append({
            "policy_id": row['policy_id'],
            "user_id": row['user_id'],
            "user_email": row['email'],
            "tenant_id": row['tenant_id'],
            "resource": policy_data.get('resource', ''),
            "actions": policy_data.get('actions', []),
            "conditions": policy_data.get('conditions'),
            "created_at": row['created_at'].isoformat() if row['created_at'] else None,
            "last_modified": row['last_modified'].isoformat() if row['last_modified'] else None
        })
    
    logger.info(f"Retrieved {len(policies)} policies for tenant {tenant_id}")
    
    return {
        "data": policies,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_items": total,
            "total_pages": (total + page_size - 1) // page_size if page_size > 0 else 0
        }
    }
