import asyncpg
from pathlib import Path
from uuid import uuid4
from datetime import datetime, timedelta, timezone
import orjson

from fastapi_mail import FastMail, MessageSchema, MessageType
from pydantic import EmailStr, NameEmail

from ..audit_logs import AuditLogger
from ..core.config import JWT_SECRET, APP_BASE_URL, APP_NAME
from ..core.email_config import configuration
from ..core.jwt_utils import create_jwt_token
from ..core.security import hash_password
from ..database.queries import QUERIES
from ..models.onboarding import TenantCreate, RootUserCreate, Policy, TenantOnboardingRequest
from typing import List

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"

def _load_email_template(template_name: str, **kwargs) -> str:
    """Load and render an email template from file."""
    template_path = TEMPLATES_DIR / template_name
    template = template_path.read_text(encoding="utf-8")
    return template.format(
        app_name=APP_NAME,
        year=datetime.now().year,
        **kwargs
    )


def _build_verification_email_html(first_name: str, verify_url: str) -> str:
    """Build verification email using template."""
    return _load_email_template(
        "onboarding/verification.html",
        first_name=first_name,
        verify_url=verify_url
    )


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


async def send_verification_email(
        first_name: str,
        last_name: str,
        user_email: EmailStr,
        user_id: str,
        tenant_id: str
):
    payload = {
        "sub": user_email,
        "user_id": user_id,
        "tenant_id": tenant_id,
        "exp": datetime.now(timezone.utc) + timedelta(hours=24)
    }
    token = await create_jwt_token(payload=payload, secret_key=JWT_SECRET)

    verify_url = f"{APP_BASE_URL}/api/v1/onboarding/email/verify?token={token}"

    msg = MessageSchema(
        body=_build_verification_email_html(first_name, verify_url),
        subject=f"Verify your {APP_NAME} account",
        recipients=[NameEmail(name=f"{first_name} {last_name}", email=str(user_email))],
        subtype=MessageType.html
    )
    fastmail = FastMail(config=configuration)
    await fastmail.send_message(msg)

async def onboard_tenant(
        dbconnection: asyncpg.Connection,
        request: TenantOnboardingRequest,
        logger: AuditLogger
) -> dict:
    tenant_id = None
    user_id = None

    try:
        async with dbconnection.transaction():
            try:
                tenant_id = await create_tenant(dbconnection, request.tenant, request.user.email)
                logger.info(f"Created tenant: {tenant_id}")
            except Exception as e:
                await logger.force_error(
                    message=f"Failed to create tenant: {tenant_id}", exception=str(e)
                )
                raise Exception(f"Failed to create tenant: {str(e)}")

            try:
                user_id = await create_user(dbconnection, tenant_id, request.user)
                logger.info(f"Created user: {user_id} for tenant: {tenant_id}")
            except Exception as e:
                await logger.force_error(
                    f"unable to create user: {user_id}", exception=str(e)
                )
                raise Exception(f"Failed to create user: {str(e)}")

            # Assign policies
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
            except Exception as e:
                raise Exception(f"Failed to assign policies: {str(e)}")

            # Create tenant policies (optional)
            if hasattr(request, 'tenant_policies') and request.tenant_policies:
                try:
                    await create_tenant_policies(dbconnection, tenant_id, request.tenant_policies)
                    logger.info(f"Created tenant-level policies for tenant: {tenant_id}")
                except Exception as e:
                    raise Exception(f"Failed to create tenant policies: {str(e)}")

        # Send verification email
        email_sent = False
        try:
            await send_verification_email(
                user_email=request.user.email, user_id=user_id, tenant_id=tenant_id,
                first_name=request.user.first_name,
                last_name=request.user.last_name
            )
            email_sent = True
            logger.info(f"Verification email sent to: {request.user.email}")
        except Exception as email_error:
            await logger.force_info(f"Warning: Failed to send verification email: {email_error}")
            # Don't fail the entire operation for email issues

        return {
            "tenant_id": tenant_id,
            "user_id": user_id,
            "message": f"Successfully created new tenant - root: {request.user.email}",
            "verification_email_sent": email_sent,
            "tenant_name": request.tenant.name,
            "admin_email": request.user.email
        }

    except Exception as e:
        await logger.force_error(f"Tenant onboarding failed: {str(e)}")
        raise Exception(f"Tenant onboarding failed: {str(e)}")