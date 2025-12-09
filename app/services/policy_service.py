from typing import List, Optional
from datetime import datetime, timezone
from uuid import uuid4

import asyncpg
import orjson
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
        policy_data = orjson.loads(row['policy']) if isinstance(row['policy'], str) else row['policy']
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
    
    policy_data = orjson.loads(row['policy']) if isinstance(row['policy'], str) else row['policy']
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
    policy_json = orjson.dumps({
        "resource": policy.resource,
        "actions": policy.actions,
        "conditions": policy.conditions or {}
    }).decode('utf-8')
    
    result = await db.execute(
        """
        INSERT INTO user_policies (tenant_id, user_id, policy_id, policy)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT DO NOTHING
        """,
        tenant_id, user_id, policy.policy_id, policy_json
    )
    if result == "INSERT 0 0":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Policy '{policy.policy_id}' already exists for this user"
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
    
    policy_json = orjson.dumps({
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
    policy_json = orjson.dumps({
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
    
    count_query = "SELECT COUNT(*) FROM user_policies"
    total = await db.fetchval(count_query)
    
    query = """
        SELECT up.policy_id, up.user_id, up.tenant_id, up.policy, 
               up.created_at, up.last_modified, u.email
        FROM user_policies up
        JOIN users u ON up.user_id = u.id
        ORDER BY up.created_at DESC
        LIMIT $1 OFFSET $2
    """
    rows = await db.fetch(query, page_size, offset)
    
    policies = []
    for row in rows:
        policy_data = orjson.loads(row['policy']) if isinstance(row['policy'], str) else row['policy']
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


async def create_tenant_policy_template(
    db: asyncpg.Connection,
    tenant_id: str,
    policy_id: str,
    policies: dict,
    roles: List[str],
    logger: AuditLogger
) -> dict:
    """
    Create a tenant-level policy template.
    These are reusable policy definitions that can be assigned to users.
    """
    template_id = str(uuid4())
    policies_json = orjson.dumps(policies).decode('utf-8')
    
    result = await db.execute(
        """
        INSERT INTO tenant_policies (id, tenant_id, policies, roles)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT DO NOTHING
        """,
        template_id, tenant_id, policies_json, roles
    )
    
    if result == "INSERT 0 0":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Policy template creation failed"
        )
    
    logger.audit(
        action="tenant_policy_create",
        tenant_id=tenant_id,
        resource=policy_id,
        decision="Tenant Policy Template Created"
    )
    
    return {
        "id": template_id,
        "tenant_id": tenant_id,
        "policy_id": policy_id,
        "policies": policies,
        "roles": roles
    }


async def get_tenant_policy_templates(
    db: asyncpg.Connection,
    tenant_id: str,
    logger: AuditLogger
) -> List[dict]:
    """Get all policy templates for a tenant."""
    query = """
        SELECT id, tenant_id, policies, roles, created_at, last_modified
        FROM tenant_policies
        WHERE tenant_id = $1
        ORDER BY created_at DESC
    """
    rows = await db.fetch(query, tenant_id)
    
    templates = []
    for row in rows:
        policies = orjson.loads(row['policies']) if isinstance(row['policies'], str) else row['policies']
        templates.append({
            "id": row['id'],
            "tenant_id": row['tenant_id'],
            "policies": policies,
            "roles": row['roles'] or [],
            "created_at": row['created_at'].isoformat() if row['created_at'] else None,
            "last_modified": row['last_modified'].isoformat() if row['last_modified'] else None
        })
    
    logger.info(f"Retrieved {len(templates)} policy templates for tenant {tenant_id}")
    return templates


async def get_tenant_policy_template_by_id(
    db: asyncpg.Connection,
    tenant_id: str,
    template_id: str,
    logger: AuditLogger
) -> Optional[dict]:
    """Get a specific policy template by ID."""
    query = """
        SELECT id, tenant_id, policies, roles, created_at, last_modified
        FROM tenant_policies
        WHERE id = $1 AND tenant_id = $2
    """
    row = await db.fetchrow(query, template_id, tenant_id)
    
    if not row:
        return None
    
    policies = orjson.loads(row['policies']) if isinstance(row['policies'], str) else row['policies']
    return {
        "id": row['id'],
        "tenant_id": row['tenant_id'],
        "policies": policies,
        "roles": row['roles'] or [],
        "created_at": row['created_at'].isoformat() if row['created_at'] else None,
        "last_modified": row['last_modified'].isoformat() if row['last_modified'] else None
    }


async def update_tenant_policy_template(
    db: asyncpg.Connection,
    tenant_id: str,
    template_id: str,
    policies: Optional[dict],
    roles: Optional[List[str]],
    logger: AuditLogger
) -> dict:
    """Update a tenant policy template."""
    existing = await get_tenant_policy_template_by_id(db, tenant_id, template_id, logger)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy template '{template_id}' not found"
        )
    
    new_policies = policies if policies is not None else existing['policies']
    new_roles = roles if roles is not None else existing['roles']
    
    policies_json = orjson.dumps(new_policies).decode('utf-8')
    
    await db.execute(
        """
        UPDATE tenant_policies
        SET policies = $3, roles = $4, last_modified = NOW()
        WHERE id = $1 AND tenant_id = $2
        """,
        template_id, tenant_id, policies_json, new_roles
    )
    
    logger.audit(
        action="tenant_policy_update",
        tenant_id=tenant_id,
        resource=template_id,
        decision="Tenant Policy Template Updated"
    )
    
    return {
        "id": template_id,
        "tenant_id": tenant_id,
        "policies": new_policies,
        "roles": new_roles
    }


async def delete_tenant_policy_template(
    db: asyncpg.Connection,
    tenant_id: str,
    template_id: str,
    logger: AuditLogger
) -> bool:
    """Delete a tenant policy template."""
    result = await db.execute(
        """
        DELETE FROM tenant_policies
        WHERE id = $1 AND tenant_id = $2
        """,
        template_id, tenant_id
    )
    
    if result == "DELETE 0":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy template '{template_id}' not found"
        )
    
    logger.audit(
        action="tenant_policy_delete",
        tenant_id=tenant_id,
        resource=template_id,
        decision="Tenant Policy Template Deleted"
    )
    
    return True


async def assign_template_to_user(
    db: asyncpg.Connection,
    tenant_id: str,
    template_id: str,
    user_id: str,
    logger: AuditLogger
) -> PolicyResponse:
    """
    Assign a tenant policy template to a user.
    Creates a user_policy from the template.
    """
    # Get the template
    template = await get_tenant_policy_template_by_id(db, tenant_id, template_id, logger)
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy template '{template_id}' not found"
        )
    
    # Create the user policy from template
    policies = template['policies']
    
    policy = PolicyCreate(
        policy_id=policies.get('policy_id'),
        resource=policies.get('resource', '*'),
        actions=policies.get('actions', []),
        conditions=policies.get('conditions')
    )
    
    return await create_policy(db, tenant_id, user_id, policy, logger)
