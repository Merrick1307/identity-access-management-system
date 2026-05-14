import asyncpg
from uuid import uuid4
import orjson
from fastapi import BackgroundTasks

from ..audit_logs import AuditLogger
from ..core.security import hash_password
from ..database.queries import QUERIES
from ..services.email_service import get_email_service
from ..models.onboarding import TenantCreate, RootUserCreate, Policy, TenantOnboardingRequest
from typing import List


async def create_tenant(
        connection: asyncpg.Connection,
        tenant_data: TenantCreate,
        root_email: str
) -> str | None:
    tenant_id = str(uuid4())
    await connection.execute(
        QUERIES["tenant_insert"],
        tenant_id, tenant_data.name, tenant_data.domain, root_email
    )
    return tenant_id


async def create_user(
        connection: asyncpg.Connection,
        tenant_id: str,
        user_data: RootUserCreate
) -> str:
    user_id = str(uuid4())
    hashed_password = hash_password(user_data.password)
    await connection.execute(
        """INSERT INTO users (
            id, tenant_id, email, password, first_name, last_name, role
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)""",
        user_id, tenant_id, user_data.email, hashed_password,
        user_data.first_name, user_data.last_name, user_data.role
    )
    return user_id


async def assign_policies(
        connection: asyncpg.Connection,
        tenant_id: str, user_id: str,
        policies: List[Policy]
):
    policies_tuples: list[tuple] = [
        (tenant_id, user_id, policy.policy_id, orjson.dumps(policy.policy).decode())
        for policy in policies
    ]
    if len(policies_tuples) == 0:
        return
    await connection.executemany(
        """INSERT INTO user_policies (
            tenant_id, user_id, policy_id, policy
        ) VALUES ($1, $2, $3, $4)""",
        policies_tuples
    )


async def create_tenant_policies(
        connection: asyncpg.Connection,
        tenant_id: str,
        policies: List[Policy]
):
    policies_tuples: list[tuple] = [
        (tenant_id,policy.policy_id, orjson.dumps(policy.policy).decode())
        for policy in policies
    ]
    if len(policies_tuples) == 0:
        return True
    await connection.executemany(
        """INSERT INTO tenant_policies (
        tenant_id, policy_id, policy
        ) VALUES ($1, $2, $3)""",
        policies_tuples
    )
    return True


async def onboard_tenant(
        dbconnection: asyncpg.Connection,
        request: TenantOnboardingRequest,
        background_tasks: BackgroundTasks,
        logger: AuditLogger
) -> dict:
    tenant_id = None
    user_id = None

    try:
        async with dbconnection.transaction():
            try:
                tenant_id = await create_tenant(dbconnection, request.tenant, request.user.email)
                logger.info(f"Created tenant: {tenant_id}")
            except Exception as exc:
                await logger.force_error(
                    message=f"Failed to create tenant for {request.user.email}",
                    exception=str(exc),
                )
                raise

            try:
                user_id = await create_user(dbconnection, tenant_id, request.user)
                logger.info(f"Created user: {user_id} for tenant: {tenant_id}")
            except Exception as exc:
                await logger.force_error(
                    f"Unable to create user for tenant: {tenant_id}",
                    exception=str(exc),
                )
                raise

            try:
                default_policies = [
                    Policy(
                        policy_id="admin_access",
                        policy={
                            "resource": "all",
                            "actions": ["manage", "write", "archive", "delete"],
                            "conditions": {}
                        }
                    )
                ]
                await assign_policies(dbconnection, tenant_id, user_id, default_policies)
                logger.info(f"Assigned default policies to user: {user_id}")
            except Exception as exc:
                await logger.force_error(
                    f"Failed to assign default policies to user: {user_id}",
                    exception=str(exc),
                )
                raise

            if hasattr(request, 'tenant_policies') and request.tenant_policies:
                try:
                    await create_tenant_policies(dbconnection, tenant_id, request.tenant_policies)
                    logger.info(f"Created tenant-level policies for tenant: {tenant_id}")
                except Exception as exc:
                    await logger.force_error(
                        f"Failed to create tenant policies for tenant: {tenant_id}",
                        exception=str(exc),
                    )
                    raise

        background_tasks.add_task(
            get_email_service().send_verification_email,
            user_email=request.user.email,
            user_id=user_id,
            tenant_id=tenant_id,
            first_name=request.user.first_name,
            last_name=request.user.last_name,
            verification_token=None
        )
        logger.info(f"Verification email sent to: {request.user.email}")

        return {
            "tenant_id": tenant_id,
            "user_id": user_id,
            "message": f"Successfully created new tenant - root: {request.user.email}",
            "verification_email_sent": True,
            "tenant_name": request.tenant.name,
            "admin_email": request.user.email
        }

    except Exception as exc:
        await logger.force_error(f"Tenant onboarding failed: {type(exc).__name__}: {exc}")
        raise
