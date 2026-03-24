import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

import asyncpg
import bcrypt
import jwt
from fastapi import APIRouter, Request, Depends, Form, status, Query
from fastapi_mail import FastMail, MessageSchema, MessageType
from pydantic import BaseModel, EmailStr, NameEmail

from app.audit_logs import AuditLogger, background_logger
from app.core.config import JWT_SECRET, ALGORITHM, MAIL_FROM, APP_BASE_URL, APP_NAME
from app.core.email_utils import configuration
from app.core.jwt_utils import create_jwt_token, create_purpose_token, decode_purpose_token
from app.core.responses import success_response, error_response, created_response, OrjsonResponse
from app.database import get_database_pool, get_database_pool_no_tenant
from app.services.onboarding import send_verification_email
from app.sso.oidc.services import OIDCService
from app.sso.oidc.template_utils import render_signup_page, render_verification_sent_page, _build_invitation_email_html

router = APIRouter()


async def send_invitation_email(
    *,
    recipient_email: str,
    recipient_name: str,
    inviter_name: str,
    organization_name: str,
    role: str,
    invitation_token: str,
    expires_at: datetime,
    client_name: Optional[str] = None,
):
    base_url = APP_BASE_URL.rstrip("/")
    accept_url = f"{base_url}/api/v1/oidc/signup?invitation={invitation_token}"

    html = _build_invitation_email_html(
        recipient_name=recipient_name,
        inviter_name=inviter_name,
        organization_name=organization_name,
        role=role or "member",
        accept_url=accept_url,
        expires_at=expires_at.strftime("%Y-%m-%d %H:%M UTC"),
        client_name=client_name,
    )

    msg = MessageSchema(
        subject=f"Invitation to join {organization_name} on {APP_NAME}",
        recipients=[NameEmail(name=recipient_name, email=recipient_email)],
        body=html,
        subtype=MessageType.html,
    )

    fm = FastMail(config=configuration)
    await fm.send_message(msg)


def generate_id() -> str:
    return secrets.token_hex(16)


class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str
    invitation_token: Optional[str] = None


class InvitationRequest(BaseModel):
    email: EmailStr
    role: Optional[str] = None
    client_id: Optional[str] = None


@router.get("/signup")
async def signup_page(
    request: Request,
    client_id: Optional[str] = Query(None),
    redirect_uri: Optional[str] = Query(None),
    invitation: Optional[str] = Query(None),
    db: asyncpg.Connection = Depends(get_database_pool_no_tenant)
):
    """
    Signup page - supports both self-service and invitation-based signup
    """
    client_name = None
    invitation_email = None
    invitation_token = None
    
    if client_id:
        client = await OIDCService.validate_client(db, client_id)
        if client:
            client_name = client["name"]
    
    if invitation:
        try:
            payload = jwt.decode(invitation, JWT_SECRET, algorithms=[ALGORITHM or "HS256"])
            invitation_id = payload.get("invitation_id")
            if invitation_id:
                invite = await db.fetchrow(
                    """SELECT email FROM user_invitations 
                       WHERE id = $1 AND accepted_at IS NULL AND expires_at > NOW()""",
                    invitation_id
                )
                if invite:
                    invitation_email = invite["email"]
                    invitation_token = invitation
        except jwt.PyJWTError:
            pass
    
    return render_signup_page(
        request=request,
        client_name=client_name,
        client_id=client_id,
        redirect_uri=redirect_uri,
        invitation_email=invitation_email,
        invitation_token=invitation_token
    )


@router.post("/signup")
async def signup_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    first_name: str = Form(...),
    last_name: str = Form(...),
    client_id: str = Form(""),
    redirect_uri: str = Form(""),
    invitation_token: str = Form(""),
    db: asyncpg.Connection = Depends(get_database_pool_no_tenant),
    logger: AuditLogger = Depends(background_logger)
):
    """Handle signup form submission"""
    client_name = None
    tenant_id = None
    role = None
    
    if client_id:
        client = await OIDCService.validate_client(db, client_id)
        if client:
            client_name = client["name"]
            tenant_id = client["tenant_id"]
    
    if password != confirm_password:
        return render_signup_page(
            request=request,
            client_name=client_name,
            client_id=client_id,
            redirect_uri=redirect_uri,
            error="Passwords do not match"
        )
    
    if len(password) < 8:
        return render_signup_page(
            request=request,
            client_name=client_name,
            client_id=client_id,
            redirect_uri=redirect_uri,
            error="Password must be at least 8 characters"
        )
    
    if invitation_token:
        try:
            payload = jwt.decode(invitation_token, JWT_SECRET, algorithms=[ALGORITHM or "HS256"])
            invitation_id = payload.get("invitation_id")
            invite = await db.fetchrow(
                """SELECT * FROM user_invitations 
                   WHERE id = $1 AND accepted_at IS NULL AND expires_at > NOW()""",
                invitation_id
            )
            if invite:
                tenant_id = invite["tenant_id"]
                role = invite["role"]
                email = invite["email"]
            else:
                return render_signup_page(
                    request=request,
                    client_name=client_name,
                    client_id=client_id,
                    redirect_uri=redirect_uri,
                    error="Invalid or expired invitation"
                )
        except jwt.PyJWTError:
            return render_signup_page(
                request=request,
                client_name=client_name,
                client_id=client_id,
                redirect_uri=redirect_uri,
                error="Invalid invitation token"
            )
    
    if not tenant_id:
        return render_signup_page(
            request=request,
            client_name=client_name,
            client_id=client_id,
            redirect_uri=redirect_uri,
            error="Unable to determine organization. Please use a valid signup link."
        )
    
    existing = await db.fetchrow(
        "SELECT id FROM users WHERE email = $1 AND tenant_id = $2",
        email, tenant_id
    )
    if existing:
        return render_signup_page(
            request=request,
            client_name=client_name,
            client_id=client_id,
            redirect_uri=redirect_uri,
            error="An account with this email already exists"
        )
    
    user_id = generate_id()
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    
    await db.execute(
        """INSERT INTO users (id, tenant_id, email, password, first_name, last_name, role, is_active, email_verified)
           VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, FALSE)""",
        user_id, tenant_id, email, password_hash, first_name, last_name, role
    )
    
    if invitation_token:
        try:
            payload = jwt.decode(invitation_token, JWT_SECRET, algorithms=[ALGORITHM or "HS256"])
            invitation_id = payload.get("invitation_id")
            await db.execute(
                "UPDATE user_invitations SET accepted_at = NOW() WHERE id = $1",
                invitation_id
            )
        except jwt.PyJWTError:
            pass
    
    verification_payload = {
        "user_id": user_id,
        "tenant_id": tenant_id,
        "purpose": "email_verify",
        "exp": datetime.now(timezone.utc) + timedelta(hours=24),
        "iat": datetime.now(timezone.utc)
    }
    verification_token = create_purpose_token(verification_payload, JWT_SECRET, ALGORITHM or "HS256")
    
    logger.audit(
        resource="/oidc/signup",
        action="user_registered",
        user_id=user_id,
        tenant_id=tenant_id,
        decision=f"User {email} registered"
    )

    await send_verification_email(
        first_name=first_name,
        last_name=last_name,
        user_email=email,
        user_id=user_id,
        verification_token=verification_token,
        tenant_id=tenant_id
    )

    return render_verification_sent_page(request, email)


@router.post("/signup/api", response_class=OrjsonResponse)
async def signup_api(
    request: SignupRequest,
    client_id: Optional[str] = Query(None),
    db: asyncpg.Connection = Depends(get_database_pool_no_tenant),
    logger: AuditLogger = Depends(background_logger)
):
    """
    API endpoint for user signup (JSON)
    
    Used by SPAs and mobile apps
    """
    tenant_id = None
    role = None
    
    if client_id:
        client = await OIDCService.validate_client(db, client_id)
        if client:
            tenant_id = client["tenant_id"]
    
    if request.invitation_token:
        try:
            payload = jwt.decode(request.invitation_token, JWT_SECRET, algorithms=[ALGORITHM or "HS256"])
            invitation_id = payload.get("invitation_id")
            invite = await db.fetchrow(
                """SELECT * FROM user_invitations 
                   WHERE id = $1 AND accepted_at IS NULL AND expires_at > NOW()""",
                invitation_id
            )
            if invite:
                tenant_id = invite["tenant_id"]
                role = invite["role"]
            else:
                return error_response("invalid_invitation", "Invalid or expired invitation", status.HTTP_400_BAD_REQUEST)
        except jwt.PyJWTError:
            return error_response("invalid_token", "Invalid invitation token", status.HTTP_400_BAD_REQUEST)
    
    if not tenant_id:
        return error_response("invalid_request", "Unable to determine organization", status.HTTP_400_BAD_REQUEST)
    
    existing = await db.fetchrow(
        "SELECT id FROM users WHERE email = $1 AND tenant_id = $2",
        request.email, tenant_id
    )
    if existing:
        return error_response("user_exists", "An account with this email already exists", status.HTTP_409_CONFLICT)
    
    if len(request.password) < 8:
        return error_response("weak_password", "Password must be at least 8 characters", status.HTTP_400_BAD_REQUEST)
    
    user_id = generate_id()
    password_hash = bcrypt.hashpw(request.password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    
    await db.execute(
        """INSERT INTO users (id, tenant_id, email, password, first_name, last_name, role, is_active, email_verified)
           VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, FALSE)""",
        user_id, tenant_id, request.email, password_hash, request.first_name, request.last_name, role
    )
    
    if request.invitation_token:
        try:
            payload = jwt.decode(request.invitation_token, JWT_SECRET, algorithms=[ALGORITHM or "HS256"])
            invitation_id = payload.get("invitation_id")
            await db.execute(
                "UPDATE user_invitations SET accepted_at = NOW() WHERE id = $1",
                invitation_id
            )
        except jwt.PyJWTError:
            pass
    
    verification_payload = {
        "user_id": user_id,
        "tenant_id": tenant_id,
        "purpose": "email_verify",
        "exp": datetime.now(timezone.utc) + timedelta(hours=24),
        "iat": datetime.now(timezone.utc)
    }
    verification_token = create_purpose_token(verification_payload, JWT_SECRET, ALGORITHM or "HS256")
    
    logger.audit(
        resource="/oidc/signup/api",
        action="user_registered",
        user_id=user_id,
        tenant_id=tenant_id,
        decision=f"User {request.email} registered via API"
    )
    
    return created_response(
        data={
            "user_id": user_id,
            "email": request.email,
            "verification_required": True,
            "verification_token": verification_token
        },
        message="Account created. Please verify your email."
    )


@router.post("/invite", response_class=OrjsonResponse)
async def create_invitation(
    request: Request,
    invitation: InvitationRequest,
    db: asyncpg.Connection = Depends(get_database_pool),
    logger: AuditLogger = Depends(background_logger)
):
    """
    Create an invitation for a new user
    
    Requires authentication - inviter must be an admin
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return error_response("unauthorized", "Authentication required", status.HTTP_401_UNAUTHORIZED)
    
    token = auth_header[7:]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM or "HS256"])
        inviter_id = payload.get("user_id")
        tenant_id = payload.get("tenant_id")
    except jwt.PyJWTError:
        return error_response("invalid_token", "Invalid or expired token", status.HTTP_401_UNAUTHORIZED)
    
    existing = await db.fetchrow(
        """SELECT id FROM user_invitations 
           WHERE email = $1 AND tenant_id = $2 AND accepted_at IS NULL AND expires_at > NOW()""",
        invitation.email, tenant_id
    )
    if existing:
        return error_response("invitation_exists", "A pending invitation already exists for this email", status.HTTP_409_CONFLICT)
    
    existing_user = await db.fetchrow(
        "SELECT id FROM users WHERE email = $1 AND tenant_id = $2",
        invitation.email, tenant_id
    )
    if existing_user:
        return error_response("user_exists", "A user with this email already exists", status.HTTP_409_CONFLICT)
    
    invitation_id = generate_id()
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    
    await db.execute(
        """INSERT INTO user_invitations (id, tenant_id, client_id, email, role, invited_by, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7)""",
        invitation_id, tenant_id, invitation.client_id, invitation.email, invitation.role, inviter_id, expires_at
    )
    
    invitation_jwt = create_purpose_token(
        {
            "invitation_id": invitation_id,
            "purpose": "invitation",
            "exp": expires_at,
            "iat": datetime.now(timezone.utc)
        },
        JWT_SECRET,
        ALGORITHM or "HS256"
    )
    
    logger.audit(
        resource="/oidc/invite",
        action="invitation_created",
        user_id=inviter_id,
        tenant_id=tenant_id,
        decision=f"Invited {invitation.email}"
    )

    tenant = await db.fetchrow(
        "SELECT name FROM tenants WHERE id = $1",
        tenant_id
    )
    organization_name = tenant["name"] if tenant else "your organization"

    client_name = None
    if invitation.client_id:
        client = await OIDCService.validate_client(db, invitation.client_id)
        if client:
            client_name = client["name"]

    inviter_name = payload.get("sub") or "An administrator"

    try:
        await send_invitation_email(
            recipient_email=invitation.email,
            recipient_name=invitation.email,
            inviter_name=inviter_name,
            organization_name=organization_name,
            role=invitation.role or "member",
            invitation_token=invitation_jwt,
            expires_at=expires_at,
            client_name=client_name,
        )
    except Exception as email_error:
        await logger.force_info(f"Warning: Failed to send invitation email: {email_error}")
    
    return created_response(
        data={
            "invitation_id": invitation_id,
            "email": invitation.email,
            "expires_at": expires_at.isoformat(),
            "invitation_link": f"{APP_BASE_URL}/api/v1/oidc/signup?invitation={invitation_jwt}"
        },
        message="Invitation created successfully"
    )


@router.get("/invitations", response_class=OrjsonResponse)
async def list_invitations(
    request: Request,
    db: asyncpg.Connection = Depends(get_database_pool)
):
    """List pending invitations for the tenant"""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return error_response("unauthorized", "Authentication required", status.HTTP_401_UNAUTHORIZED)
    
    token = auth_header[7:]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM or "HS256"])
        tenant_id = payload.get("tenant_id")
    except jwt.PyJWTError:
        return error_response("invalid_token", "Invalid or expired token", status.HTTP_401_UNAUTHORIZED)
    
    invitations = await db.fetch(
        """SELECT id, email, role, invited_by, expires_at, created_at, accepted_at
           FROM user_invitations 
           WHERE tenant_id = $1
           ORDER BY created_at DESC""",
        tenant_id
    )
    
    return success_response(
        data=[dict(inv) for inv in invitations],
        message=f"Found {len(invitations)} invitations"
    )


@router.delete("/invitations/{invitation_id}", response_class=OrjsonResponse)
async def revoke_invitation(
    invitation_id: str,
    request: Request,
    db: asyncpg.Connection = Depends(get_database_pool),
    logger: AuditLogger = Depends(background_logger)
):
    """Revoke a pending invitation"""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return error_response("unauthorized", "Authentication required", status.HTTP_401_UNAUTHORIZED)
    
    token = auth_header[7:]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM or "HS256"])
        user_id = payload.get("user_id")
        tenant_id = payload.get("tenant_id")
    except jwt.PyJWTError:
        return error_response("invalid_token", "Invalid or expired token", status.HTTP_401_UNAUTHORIZED)
    
    result = await db.execute(
        """DELETE FROM user_invitations 
           WHERE id = $1 AND tenant_id = $2 AND accepted_at IS NULL""",
        invitation_id, tenant_id
    )
    
    if result == "DELETE 0":
        return error_response("not_found", "Invitation not found", status.HTTP_404_NOT_FOUND)
    
    logger.audit(
        resource=f"/oidc/invitations/{invitation_id}",
        action="invitation_revoked",
        user_id=user_id,
        tenant_id=tenant_id,
        decision="Invitation deleted"
    )
    
    return success_response(message="Invitation revoked")
