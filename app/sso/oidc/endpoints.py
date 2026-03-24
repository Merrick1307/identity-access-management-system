"""
OAuth2/OIDC Authorization Endpoints

Implements:
- /authorize - Authorization endpoint (HTML consent + JSON API)
- /token - Token endpoint (authorization_code, refresh_token, client_credentials, token_exchange)
- /userinfo - UserInfo endpoint
- /jwks - JSON Web Key Set
- /logout - End session endpoint
- /consent - Consent form submission
"""
import os

import orjson
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional
from urllib.parse import urlencode

import asyncpg
import bcrypt
import jwt
from fastapi import APIRouter, Request, Depends, Form, status, Query
from fastapi.responses import HTMLResponse, RedirectResponse

from app.audit_logs import AuditLogger, background_logger
from app.core.config import JWT_SECRET, ALGORITHM, APP_BASE_URL
from app.core.jwt_utils import create_jwt_token
from app.core.responses import success_response, error_response, OrjsonResponse
from app.database import get_database_pool, get_database_pool_no_tenant, get_revocation_manager
from app.core.token_revocation import TokenRevocationManager
from app.models.authz import Action
from app.sso.oidc.services import OIDCService
from app.sso.oidc.template_utils import (
    render_login_page,
    render_consent_page,
    render_error_page,
    render_provider_chooser_page,
)
from app.services.session_service import create_session, revoke_all_sessions
from app.services import federation_service

router = APIRouter()
HEX_DOMAIN: str = os.getenv("HEX_DOMAIN", "hexalgon.com")

def generate_id() -> str:
    return secrets.token_hex(16)


async def fetch_user_policies(db: asyncpg.Connection, user_id: str, tenant_id: str) -> dict:
    """Fetch user policies and convert to bitmask format for token inclusion."""
    rows = await db.fetch(
        """
        SELECT policy FROM user_policies 
        WHERE user_id = $1 AND tenant_id = $2
        AND (
            (policy -> 'conditions' ->> 'validity_time')::timestamptz >= NOW() 
            OR NOT (policy -> 'conditions' ? 'validity_time')
        )
        """,
        user_id, tenant_id
    )
    
    policies = []
    for row in rows:
        try:
            policy = orjson.loads(row["policy"]) if isinstance(row["policy"], str) else row["policy"]
            policies.append(policy)
        except (orjson.JSONDecodeError, TypeError):
            continue
    
    # Convert to resource -> bitmask format
    user_policy = {}
    for p in policies:
        resource = p.get("resource")
        actions = p.get("actions", [])
        if resource and actions:
            bitmask = sum(Action[a.upper()].value for a in actions if a.upper() in Action.__members__)
            user_policy[resource] = user_policy.get(resource, 0) | bitmask
    
    return user_policy


async def get_session_user(request: Request) -> Optional[dict]:
    """Extract user from session cookie or Authorization header"""
    session_token = request.cookies.get("hex_iam_session")
    if not session_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            session_token = auth_header.split(" ")[1]
    
    if not session_token:
        return None
    
    try:
        # Skip audience verification for session cookies (we created them ourselves)
        payload = jwt.decode(
            session_token, 
            JWT_SECRET, 
            algorithms=[ALGORITHM or "HS256"],
            options={"verify_aud": False}
        )
        return payload
    except jwt.PyJWTError as e:
        return None


def _provider_callback_uri(provider_id: str) -> str:
    return f"{APP_BASE_URL.rstrip('/')}/api/v1/oidc/federation/callback/{provider_id}"


def _build_session_payload(*, user: dict, tenant_id: str, client_id: str) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "sub": user["email"],
        "iss": f"https://{HEX_DOMAIN}/{tenant_id}",
        "aud": client_id,
        "user_id": str(user["id"]),
        "tenant_id": tenant_id,
        "first_name": user.get("first_name"),
        "last_name": user.get("last_name"),
        "role": user.get("role"),
        "exp": now + timedelta(hours=1),
        "iat": now,
    }


def _set_session_cookie(response, session_token: str):
    is_secure = APP_BASE_URL.startswith("https://")
    response.set_cookie(
        key="hex_iam_session",
        value=session_token,
        httponly=True,
        secure=is_secure,
        samesite="lax",
        path="/",
        max_age=3600,
    )
    return response




async def _begin_federated_authorization(
    *,
    db: asyncpg.Connection,
    provider: dict,
    tenant_id: str,
    client_id: str,
    redirect_uri: str,
    response_type: str,
    scope: str,
    state: Optional[str],
    nonce: Optional[str],
    code_challenge: Optional[str],
    code_challenge_method: Optional[str],
) -> RedirectResponse:
    upstream_state = secrets.token_urlsafe(24)
    upstream_nonce = secrets.token_urlsafe(24)
    await federation_service.create_federation_auth_transaction(
        db,
        tenant_id=tenant_id,
        provider_id=provider["id"],
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        nonce=nonce,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        upstream_state=upstream_state,
        upstream_nonce=upstream_nonce,
    )
    authorize_url = await federation_service.build_provider_authorize_url(
        provider,
        redirect_uri=_provider_callback_uri(provider["id"]),
        upstream_state=upstream_state,
        upstream_nonce=upstream_nonce,
    )
    return RedirectResponse(url=authorize_url, status_code=302)


@router.get("/authorize")
async def authorize(
    request: Request,
    client_id: str,
    redirect_uri: str,
    response_type: str = "code",
    scope: str = "openid",
    state: Optional[str] = None,
    nonce: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = "S256",
    provider_id: Optional[str] = None,
    local_login: bool = False,
    db: asyncpg.Connection = Depends(get_database_pool)
):
    """
    OAuth2 Authorization Endpoint.

    If there is no local IAM session, the endpoint can now initiate upstream
    federation to a configured identity provider before resuming the normal
    consent/code flow.
    """
    accept = request.headers.get("Accept", "")
    is_api_request = "application/json" in accept and "text/html" not in accept

    client = await OIDCService.validate_client(db, client_id)
    if not client:
        if is_api_request:
            return error_response("invalid_client", "Unknown client", status.HTTP_400_BAD_REQUEST)
        return render_error_page(
            request=request,
            title="Invalid Client",
            message="The application you're trying to sign in to is not registered. Please contact the application administrator.",
            error_code="invalid_client",
            details=f"Client ID: {client_id}",
            status_code=400
        )

    if not await OIDCService.validate_redirect_uri(db, client_id, redirect_uri):
        if is_api_request:
            return error_response("invalid_redirect_uri", "Invalid redirect URI", status.HTTP_400_BAD_REQUEST)
        return render_error_page(
            request=request,
            title="Invalid Redirect",
            message="The application provided an invalid redirect URL. This may be a misconfiguration. Please contact the application administrator.",
            error_code="invalid_redirect_uri",
            details=f"Redirect URI: {redirect_uri}",
            status_code=400
        )

    user = await get_session_user(request)

    if is_api_request:
        if user:
            return success_response({
                "status": "consent_required",
                "client_name": client["name"],
                "scopes": scope.split(),
                "user_email": user.get("sub")
            })
        providers = await federation_service.list_enabled_identity_providers(db, client["tenant_id"], protocol="oidc")
        return success_response({
            "status": "login_required",
            "client_name": client["name"],
            "login_url": f"/api/v1/oidc/login",
            "federation_providers": [
                {"id": p["id"], "name": p.get("name"), "issuer_url": p.get("issuer_url")} for p in providers
            ]
        })

    if user:
        return render_consent_page(
            request=request,
            client_name=client["name"],
            client_id=client_id,
            user_email=user.get("sub"),
            scopes=scope.split(),
            redirect_uri=redirect_uri,
            response_type=response_type,
            scope=scope,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method
        )

    if not local_login:
        providers = await federation_service.list_enabled_identity_providers(db, client["tenant_id"], protocol="oidc")
        if provider_id:
            selected = next((p for p in providers if p["id"] == provider_id), None)
            if not selected:
                return render_error_page(
                    request=request,
                    title="Unknown identity provider",
                    message="The requested identity provider is not enabled for this tenant.",
                    error_code="invalid_identity_provider",
                    details=f"Provider ID: {provider_id}",
                    status_code=400
                )
            return await _begin_federated_authorization(
                db=db,
                provider=selected,
                tenant_id=client["tenant_id"],
                client_id=client_id,
                redirect_uri=redirect_uri,
                response_type=response_type,
                scope=scope,
                state=state,
                nonce=nonce,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
            )
        if len(providers) == 1:
            return await _begin_federated_authorization(
                db=db,
                provider=providers[0],
                tenant_id=client["tenant_id"],
                client_id=client_id,
                redirect_uri=redirect_uri,
                response_type=response_type,
                scope=scope,
                state=state,
                nonce=nonce,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
            )
        if len(providers) > 1:
            return render_provider_chooser_page(
                request=request,
                client_name=client["name"],
                providers=providers,
                client_id=client_id,
                redirect_uri=redirect_uri,
                response_type=response_type,
                scope=scope,
                state=state,
                nonce=nonce,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
            )

    return render_login_page(
        request=request,
        client_name=client["name"],
        client_id=client_id,
        redirect_uri=redirect_uri,
        response_type=response_type,
        scope=scope,
        state=state,
        nonce=nonce,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method
    )


@router.post("/login")
async def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    response_type: str = Form("code"),
    scope: str = Form("openid"),
    state: str = Form(""),
    nonce: str = Form(""),
    code_challenge: str = Form(""),
    code_challenge_method: str = Form(""),
    db: asyncpg.Connection = Depends(get_database_pool),
    logger: AuditLogger = Depends(background_logger)
):
    """Handle login form submission"""
    client = await OIDCService.validate_client(db, client_id)
    if not client:
        return HTMLResponse(content="<h1>Error: Unknown client</h1>", status_code=400)
    
    tenant_id = client["tenant_id"]
    
    user = await db.fetchrow(
        """SELECT id, email, password, first_name, last_name, role, email_verified, is_active 
           FROM users WHERE email = $1 AND tenant_id = $2""",
        email, tenant_id
    )
    
    if not user:
        return render_login_page(
            request=request,
            client_name=client["name"],
            client_id=client_id,
            redirect_uri=redirect_uri,
            response_type=response_type,
            scope=scope,
            state=state or None,
            nonce=nonce or None,
            code_challenge=code_challenge or None,
            code_challenge_method=code_challenge_method or None,
            error="Invalid email or password"
        )
    
    if not bcrypt.checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
        logger.audit(
            resource="/oidc/login",
            action="login_failed",
            user_id=str(user["id"]),
            tenant_id=tenant_id,
            decision="Invalid password"
        )
        return render_login_page(
            request=request,
            client_name=client["name"],
            client_id=client_id,
            redirect_uri=redirect_uri,
            response_type=response_type,
            scope=scope,
            state=state or None,
            nonce=nonce or None,
            code_challenge=code_challenge or None,
            code_challenge_method=code_challenge_method or None,
            error="Invalid email or password"
        )
    
    if not user["is_active"]:
        return render_login_page(
            request=request,
            client_name=client["name"],
            client_id=client_id,
            redirect_uri=redirect_uri,
            response_type=response_type,
            scope=scope,
            state=state or None,
            nonce=nonce or None,
            code_challenge=code_challenge or None,
            code_challenge_method=code_challenge_method or None,
            error="Account is disabled"
        )
    
    if not user["email_verified"]:
        return render_login_page(
            request=request,
            client_name=client["name"],
            client_id=client_id,
            redirect_uri=redirect_uri,
            response_type=response_type,
            scope=scope,
            state=state or None,
            nonce=nonce or None,
            code_challenge=code_challenge or None,
            code_challenge_method=code_challenge_method or None,
            error="Please verify your email before signing in"
        )
    
    session_payload = _build_session_payload(user=dict(user), tenant_id=tenant_id, client_id=client_id)
    session_token = create_jwt_token(session_payload, JWT_SECRET)
    
    logger.audit(
        resource="/oidc/login",
        action="login_success",
        user_id=str(user["id"]),
        tenant_id=tenant_id,
        decision="User authenticated"
    )
    
    response = render_consent_page(
        request=request,
        client_name=client["name"],
        client_id=client_id,
        user_email=user["email"],
        scopes=scope.split(),
        redirect_uri=redirect_uri,
        response_type=response_type,
        scope=scope,
        state=state or None,
        nonce=nonce or None,
        code_challenge=code_challenge or None,
        code_challenge_method=code_challenge_method or None
    )
    return _set_session_cookie(response, session_token)


@router.get("/federation/callback/{provider_id}")
async def federation_callback(
    request: Request,
    provider_id: str,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None,
    db: asyncpg.Connection = Depends(get_database_pool_no_tenant),
    logger: AuditLogger = Depends(background_logger),
):
    if error:
        return render_error_page(
            request=request,
            title="External sign-in failed",
            message=error_description or "The external identity provider returned an error.",
            error_code=error,
            status_code=400,
        )

    if not code or not state:
        return render_error_page(
            request=request,
            title="Invalid federation callback",
            message="The external identity provider callback was missing required parameters.",
            error_code="invalid_callback",
            details=f"provider_id={provider_id}",
            status_code=400,
        )

    txn = await federation_service.get_federation_auth_transaction_by_state(
        db, provider_id=provider_id, upstream_state=state
    )
    if not txn:
        return render_error_page(
            request=request,
            title="Expired or unknown sign-in request",
            message="The federation handoff could not be resumed. Please try signing in again.",
            error_code="invalid_transaction",
            status_code=400,
        )

    provider = await federation_service.get_identity_provider(db, txn["tenant_id"], provider_id)
    if not provider or not provider.get("enabled", True):
        return render_error_page(
            request=request,
            title="Identity provider unavailable",
            message="The selected identity provider is no longer available for this tenant.",
            error_code="identity_provider_unavailable",
            status_code=400,
        )

    try:
        upstream_tokens = await federation_service.exchange_code_for_provider_tokens(
            provider, code=code, redirect_uri=_provider_callback_uri(provider_id)
        )
        user, _claims = await federation_service.resolve_or_provision_from_provider_tokens(
            db=db,
            tenant_id=txn["tenant_id"],
            provider=provider,
            tokens=upstream_tokens,
        )
    except Exception as exc:
        logger.error(f"federation callback failed: {exc}")
        return render_error_page(
            request=request,
            title="Federated sign-in failed",
            message="HEX IAM could not complete authentication with the external provider.",
            error_code="federation_callback_failed",
            details=str(exc),
            status_code=400,
        )

    await federation_service.consume_federation_auth_transaction(db, txn["id"])

    client = await OIDCService.validate_client(db, txn["client_id"])
    if not client:
        return render_error_page(
            request=request,
            title="Client no longer available",
            message="The downstream client application is no longer active.",
            error_code="invalid_client",
            status_code=400,
        )

    session_payload = _build_session_payload(user=user, tenant_id=txn["tenant_id"], client_id=txn["client_id"])
    session_token = create_jwt_token(session_payload, JWT_SECRET)

    logger.audit(
        resource=f"/oidc/federation/callback/{provider_id}",
        action="federated_login_success",
        user_id=str(user["id"]),
        tenant_id=txn["tenant_id"],
        decision=f"broker={provider.get('issuer_url')} client={txn['client_id']}"
    )

    response = render_consent_page(
        request=request,
        client_name=client["name"],
        client_id=txn["client_id"],
        user_email=user["email"],
        scopes=(txn.get("scope") or "openid").split(),
        redirect_uri=txn["redirect_uri"],
        response_type="code",
        scope=txn["scope"],
        state=txn.get("state"),
        nonce=txn.get("nonce"),
        code_challenge=txn.get("code_challenge"),
        code_challenge_method=txn.get("code_challenge_method"),
    )
    return _set_session_cookie(response, session_token)


@router.post("/consent")
async def consent_submit(
    request: Request,
    action: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    response_type: str = Form("code"),
    scope: str = Form("openid"),
    state: str = Form(""),
    nonce: str = Form(""),
    code_challenge: str = Form(""),
    code_challenge_method: str = Form(""),
    db: asyncpg.Connection = Depends(get_database_pool),
    logger: AuditLogger = Depends(background_logger)
):
    """Handle consent form submission"""
    user = await get_session_user(request)
    if not user:
        return RedirectResponse(
            url=f"/api/v1/oidc/authorize?client_id={client_id}&redirect_uri={redirect_uri}&response_type={response_type}&scope={scope}&state={state}",
            status_code=302
        )
    
    if action == "deny":
        params = {"error": "access_denied", "error_description": "User denied the request"}
        if state:
            params["state"] = state
        return RedirectResponse(url=f"{redirect_uri}?{urlencode(params)}", status_code=302)
    
    code = OIDCService.generate_authorization_code()
    
    await OIDCService.store_authorization_code(
        db=db,
        code=code,
        client_id=client_id,
        user_id=user["user_id"],
        tenant_id=user["tenant_id"],
        redirect_uri=redirect_uri,
        scope=scope,
        code_challenge=code_challenge or None,
        code_challenge_method=code_challenge_method or None,
        nonce=nonce or None
    )
    
    logger.audit(
        resource="/oidc/consent",
        action="consent_granted",
        user_id=user["user_id"],
        tenant_id=user["tenant_id"],
        decision=f"Granted access to {client_id}"
    )
    
    params = {"code": code}
    if state:
        params["state"] = state
    
    return RedirectResponse(url=f"{redirect_uri}?{urlencode(params)}", status_code=302)


@router.post("/token")
async def token_endpoint(
    request: Request,
    db: asyncpg.Connection = Depends(get_database_pool),
    logger: AuditLogger = Depends(background_logger)
):
    """
    OAuth2 Token Endpoint
    
    Supports:
    - authorization_code grant
    - refresh_token grant
    - client_credentials grant
    - token_exchange grant
    """
    content_type = request.headers.get("content-type", "")
    if "application/x-www-form-urlencoded" in content_type:
        form = await request.form()
        data = dict(form)
    else:
        data = await request.json()
    
    grant_type = data.get("grant_type")
    client_id = data.get("client_id")
    client_secret = data.get("client_secret")

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Basic "):
        import base64
        try:
            decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
            client_id, client_secret = decoded.split(":", 1)
        except Exception:
            pass
    
    client = await OIDCService.validate_client(db, client_id, client_secret)
    if not client:
        logger.error("invalid client")
        return OrjsonResponse(
            content={"error": "invalid_client", "error_description": "Invalid client credentials"},
            status_code=401
        )
    tenant_id: str = client.get("tenant_id")

    if grant_type == "authorization_code":
        code = data.get("code")
        redirect_uri = data.get("redirect_uri")
        code_verifier = data.get("code_verifier")
        
        if not code or not redirect_uri:
            logger.error("invalid request")
            return OrjsonResponse(
                content={"error": "invalid_request", "error_description": "Missing code or redirect_uri"},
                status_code=400
            )
        
        auth_code = await OIDCService.validate_authorization_code(db, code, client_id, redirect_uri, code_verifier)
        if not auth_code:
            logger.error("invalid grant")
            return OrjsonResponse(
                content={"error": "invalid_grant", "error_description": "Invalid or expired authorization code"},
                status_code=400
            )
        
        user = await db.fetchrow(
            "SELECT id, email, first_name, last_name, role FROM users WHERE id = $1",
            auth_code["user_id"]
        )
        
        if not user:
            return OrjsonResponse(
                content={"error": "invalid_grant", "error_description": "User not found"},
                status_code=400
            )
        
        # Fetch user policies for token inclusion
        user_policies = await fetch_user_policies(db, str(user["id"]), auth_code["tenant_id"])
        
        now = datetime.now(timezone.utc)
        access_payload = {
            "sub": user["email"],
            "iss": f"https://{HEX_DOMAIN}/{tenant_id}",
            "user_id": str(user["id"]),
            "tenant_id": auth_code["tenant_id"],
            "aud": client_id,
            "role": user["role"],
            "scope": auth_code["scope"],
            "policy": user_policies,
            "exp": now + timedelta(hours=1),
            "iat": now
        }
        access_token = create_jwt_token(access_payload, JWT_SECRET)
        
        refresh_token = await OIDCService.create_refresh_token(
            db, str(user["id"]), auth_code["tenant_id"], client_id, auth_code["scope"]
        )
        
        response_data = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": refresh_token,
            "scope": auth_code["scope"]
        }
        
        if "openid" in auth_code["scope"]:
            id_token = await OIDCService.create_id_token(
                user_id=str(user["id"]),
                email=user["email"],
                tenant_id=auth_code["tenant_id"],
                client_id=client_id,
                nonce=auth_code.get("nonce"),
                first_name=user["first_name"],
                last_name=user["last_name"],
                role=user["role"]
            )
            response_data["id_token"] = id_token
        
        logger.audit(
            resource="/oidc/token",
            action="token_issued",
            user_id=str(user["id"]),
            tenant_id=auth_code["tenant_id"],
            decision="authorization_code grant"
        )
        
        return OrjsonResponse(content=response_data)
    
    elif grant_type == "refresh_token":
        refresh_token = data.get("refresh_token")
        if not refresh_token:
            return OrjsonResponse(
                content={"error": "invalid_request", "error_description": "Missing refresh_token"},
                status_code=400
            )
        
        token_data = await OIDCService.validate_refresh_token(db, refresh_token, client_id)
        if not token_data:
            return OrjsonResponse(
                content={"error": "invalid_grant", "error_description": "Invalid or expired refresh token"},
                status_code=400
            )
        
        user = await db.fetchrow(
            "SELECT id, email, first_name, last_name, role FROM users WHERE id = $1",
            token_data["user_id"]
        )
        
        if not user:
            return OrjsonResponse(
                content={"error": "invalid_grant", "error_description": "User not found"},
                status_code=400
            )
        
        await OIDCService.revoke_refresh_token(db, refresh_token)
        
        # Fetch user policies for token inclusion
        user_policies = await fetch_user_policies(db, str(user["id"]), token_data["tenant_id"])
        
        now = datetime.now(timezone.utc)
        access_payload = {
            "sub": user["email"],
            "iss": f"https://{HEX_DOMAIN}/{tenant_id}",
            "user_id": str(user["id"]),
            "tenant_id": token_data["tenant_id"],
            "aud": client_id,
            "role": user["role"],
            "policy": user_policies,
            "exp": now + timedelta(hours=1),
            "iat": now
        }
        access_token = create_jwt_token(access_payload, JWT_SECRET)
        
        new_refresh_token = await OIDCService.create_refresh_token(
            db, str(user["id"]), token_data["tenant_id"], client_id, token_data.get("scope", "openid")
        )
        
        return OrjsonResponse(content={
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": new_refresh_token
        })
    
    elif grant_type == "client_credentials":
        now = datetime.now(timezone.utc)
        access_payload = {
            "sub": client_id,
            "iss": f"https://{HEX_DOMAIN}/{tenant_id}",
            "client_id": client_id,
            "aud": client_id,
            "tenant_id": client["tenant_id"],
            "grant_type": "client_credentials",
            "exp": now + timedelta(hours=1),
            "iat": now
        }
        access_token = create_jwt_token(access_payload, JWT_SECRET)
        
        logger.audit(
            resource="/oidc/token",
            action="token_issued",
            user_id=client_id,
            tenant_id=client["tenant_id"],
            decision="client_credentials grant"
        )
        
        return OrjsonResponse(content={
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600
        })

    elif grant_type == "urn:ietf:params:oauth:grant-type:token-exchange":
        subject_token = data.get("subject_token")
        requested_audience = data.get("audience")
        audience = requested_audience or client_id
        issuer_hint = data.get("issuer_hint")

        if requested_audience and requested_audience != client_id:
            return OrjsonResponse(
                content={"error": "invalid_target", "error_description": "Token exchange audience must match the authenticated client"},
                status_code=400
            )

        if not subject_token:
            return OrjsonResponse(
                content={"error": "invalid_request", "error_description": "Missing subject_token"},
                status_code=400
            )

        try:
            user, provider, claims = await federation_service.resolve_or_provision_federated_user(
                db=db,
                tenant_id=tenant_id,
                subject_token=subject_token,
                audience=audience,
                issuer_hint=issuer_hint,
            )
        except Exception as exc:
            logger.error(f"token exchange failed: {exc}")
            return OrjsonResponse(
                content={"error": "invalid_grant", "error_description": str(exc)},
                status_code=400
            )

        scope = claims.get("scope") or "openid profile email"
        user_policies = await fetch_user_policies(db, str(user["id"]), tenant_id)
        now = datetime.now(timezone.utc)
        access_payload = {
            "sub": user["email"],
            "iss": f"https://{HEX_DOMAIN}/{tenant_id}",
            "user_id": str(user["id"]),
            "tenant_id": tenant_id,
            "aud": audience,
            "role": user.get("role"),
            "scope": scope,
            "policy": user_policies,
            "amr": ["broker"],
            "broker_iss": provider["issuer_url"],
            "exp": now + timedelta(hours=1),
            "iat": now,
        }
        access_token = create_jwt_token(access_payload, JWT_SECRET)
        refresh_token = await OIDCService.create_refresh_token(
            db, str(user["id"]), tenant_id, audience, scope
        )
        response_data = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": refresh_token,
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "scope": scope,
        }
        if "openid" in scope.split():
            response_data["id_token"] = await OIDCService.create_id_token(
                user_id=str(user["id"]),
                email=user["email"],
                tenant_id=tenant_id,
                client_id=audience,
                first_name=user.get("first_name"),
                last_name=user.get("last_name"),
                role=user.get("role"),
            )

        logger.audit(
            resource="/oidc/token",
            action="token_exchanged",
            user_id=str(user["id"]),
            tenant_id=tenant_id,
            decision=f"broker={provider['issuer_url']} audience={audience}"
        )
        return OrjsonResponse(content=response_data)
    
    return OrjsonResponse(
        content={"error": "unsupported_grant_type", "error_description": f"Grant type '{grant_type}' not supported"},
        status_code=400
    )


@router.get("/userinfo")
async def userinfo(
    request: Request,
    db: asyncpg.Connection = Depends(get_database_pool)
):
    """UserInfo Endpoint - Returns claims about the authenticated user"""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return OrjsonResponse(
            content={"error": "invalid_token", "error_description": "Missing or invalid Authorization header"},
            status_code=401
        )
    
    token = auth_header[7:]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM or "HS256"])
    except jwt.PyJWTError:
        return OrjsonResponse(
            content={"error": "invalid_token", "error_description": "Invalid or expired token"},
            status_code=401
        )
    
    user_id = payload.get("user_id")
    if not user_id:
        return OrjsonResponse(content={"sub": payload.get("sub")})
    
    user = await db.fetchrow(
        """SELECT id, email, first_name, last_name, role, email_verified 
           FROM users WHERE id = $1""",
        user_id
    )
    
    if not user:
        return OrjsonResponse(
            content={"error": "invalid_token", "error_description": "User not found"},
            status_code=401
        )
    
    return OrjsonResponse(content={
        "sub": str(user["id"]),
        "email": user["email"],
        "email_verified": user["email_verified"],
        "name": f"{user['first_name']} {user['last_name']}",
        "given_name": user["first_name"],
        "family_name": user["last_name"],
        "role": user["role"],
        "tenant_id": payload.get("tenant_id")
    })


@router.get("/jwks")
async def jwks():
    """
    JSON Web Key Set endpoint
    
    For HS256 (symmetric), we return an empty keyset.
    For RS256 (asymmetric), this would return public keys.
    """
    return OrjsonResponse(content={"keys": []})


@router.post("/logout")
@router.get("/logout")
async def end_session(
    request: Request,
    id_token_hint: Optional[str] = Query(None),
    post_logout_redirect_uri: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    db: asyncpg.Connection = Depends(get_database_pool),
    revocation_manager: TokenRevocationManager = Depends(get_revocation_manager),
    logger: AuditLogger = Depends(background_logger)
):
    """
    End Session Endpoint - Logs out the user and revokes sessions.
    
    Properly revokes JTIs from active sessions to ensure tokens are invalidated.
    """
    user_id = None
    tenant_id = None
    
    # Try to get user info from id_token_hint
    if id_token_hint:
        try:
            payload = jwt.decode(id_token_hint, JWT_SECRET, algorithms=[ALGORITHM or "HS256"])
            user_id = payload.get("user_id") or payload.get("sub")
            tenant_id = payload.get("tenant_id")
        except jwt.PyJWTError:
            pass
    
    # Fallback: try session cookie
    if not user_id:
        session_token = request.cookies.get("hex_iam_session")
        if session_token:
            try:
                payload = jwt.decode(session_token, JWT_SECRET, algorithms=[ALGORITHM or "HS256"])
                user_id = payload.get("user_id")
                tenant_id = payload.get("tenant_id")
            except jwt.PyJWTError:
                pass
    
    # Revoke all sessions for this user
    if user_id and tenant_id:
        try:
            revoked_count = await revoke_all_sessions(
                db=db,
                revocation_manager=revocation_manager,
                user_id=user_id,
                tenant_id=tenant_id,
                logger=logger,
                reason="oidc_logout"
            )
            logger.audit(
                action="oidc_logout",
                user_id=user_id,
                tenant_id=tenant_id,
                resource="/oidc/logout",
                decision=f"Revoked {revoked_count} sessions"
            )
        except Exception as e:
            logger.error(f"Failed to revoke sessions during logout: {e}")
    
    # Build redirect URL
    redirect_url = post_logout_redirect_uri or "/"
    if state and post_logout_redirect_uri:
        separator = "&" if "?" in post_logout_redirect_uri else "?"
        redirect_url = f"{post_logout_redirect_uri}{separator}state={state}"
    
    response = RedirectResponse(url=redirect_url, status_code=302)
    response.delete_cookie("hex_iam_session", path="/")
    
    return response
