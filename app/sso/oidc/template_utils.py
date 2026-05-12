"""
Template utilities for OIDC endpoints.
Provides functions to render HTML templates using Jinja2.
"""
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode, urlparse
from typing import Optional, List

from fastapi import Request
from fastapi.templating import Jinja2Templates
from starlette.responses import HTMLResponse

from app.core.config import APP_NAME
from app.models.oidc import ScopeItem

BASE_DIR = Path(__file__).resolve().parent.parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

SCOPE_DESCRIPTIONS = {
    "openid": "Access your user ID",
    "profile": "Access your name and profile information",
    "email": "Access your email address",
}


def get_scope_items(scopes: List[str]) -> List[ScopeItem]:
    """Convert scope strings to ScopeItem objects with descriptions"""
    return [
        ScopeItem(name=s, description=SCOPE_DESCRIPTIONS.get(s, f"Access to {s}"))
        for s in scopes
    ]


def _provider_domain(issuer_url: Optional[str]) -> Optional[str]:
    if not issuer_url:
        return None

    candidate = issuer_url.strip()
    if not candidate:
        return None

    parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
    return parsed.hostname


def _provider_icon_url(domain: Optional[str], size: int = 64) -> Optional[str]:
    if not domain:
        return None
    return f"https://www.google.com/s2/favicons?{urlencode({'domain': domain, 'sz': size})}"


def _provider_initials(name: Optional[str], domain: Optional[str]) -> str:
    source = (name or domain or "SSO").strip()
    words = [part for part in source.replace(".", " ").replace("-", " ").split() if part]
    if not words:
        return "SS"
    if len(words) == 1:
        return words[0][:2].upper()
    return f"{words[0][0]}{words[1][0]}".upper()


def render_login_page(
    request: Request,
    client_name: str,
    client_id: str,
    redirect_uri: str,
    response_type: str,
    scope: str,
    state: Optional[str],
    nonce: Optional[str],
    code_challenge: Optional[str],
    code_challenge_method: Optional[str],
    error: Optional[str] = None
) -> HTMLResponse:
    """Render the login page using Jinja2 template"""
    return templates.TemplateResponse(
        "oidc/login.html",
        {
            "request": request,
            "client_name": client_name,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": response_type,
            "scope": scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "error": error,
        }
    )


def render_consent_page(
    request: Request,
    client_name: str,
    client_id: str,
    user_email: str,
    scopes: List[str],
    redirect_uri: str,
    response_type: str,
    scope: str,
    state: Optional[str],
    nonce: Optional[str],
    code_challenge: Optional[str],
    code_challenge_method: Optional[str],
) -> HTMLResponse:
    """Render the consent page using Jinja2 template"""
    return templates.TemplateResponse(
        "oidc/consent.html",
        {
            "request": request,
            "client_name": client_name,
            "client_id": client_id,
            "user_email": user_email,
            "scope_items": get_scope_items(scopes),
            "redirect_uri": redirect_uri,
            "response_type": response_type,
            "scope": scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
        }
    )



def render_provider_chooser_page(
    request: Request,
    client_name: str,
    providers: List[dict],
    client_id: str,
    redirect_uri: str,
    response_type: str,
    scope: str,
    state: Optional[str],
    nonce: Optional[str],
    code_challenge: Optional[str],
    code_challenge_method: Optional[str],
) -> HTMLResponse:
    """Render the upstream identity-provider chooser page using Jinja2 template."""
    base_params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": response_type,
        "scope": scope,
    }
    if state:
        base_params["state"] = state
    if nonce:
        base_params["nonce"] = nonce
    if code_challenge:
        base_params["code_challenge"] = code_challenge
    if code_challenge_method:
        base_params["code_challenge_method"] = code_challenge_method

    provider_options = []
    for provider in providers:
        params = {**base_params, "provider_id": provider["id"]}
        issuer_url = provider.get("issuer_url")
        domain = _provider_domain(issuer_url)
        display_name = provider.get("name") or domain or issuer_url or "SSO"
        provider_options.append(
            {
                "id": provider["id"],
                "name": display_name,
                "url": f"/api/v1/oidc/authorize?{urlencode(params)}",
                "issuer_url": issuer_url,
                "display_domain": domain or issuer_url,
                "icon_url": _provider_icon_url(domain),
                "initials": _provider_initials(display_name, domain),
            }
        )

    local_params = {**base_params, "local_login": "1"}
    local_login_url = f"/api/v1/oidc/authorize?{urlencode(local_params)}"

    return templates.TemplateResponse(
        "oidc/provider_chooser.html",
        {
            "request": request,
            "client_name": client_name,
            "providers": provider_options,
            "local_login_url": local_login_url,
        },
    )

def render_signup_page(
    request: Request,
    client_name: Optional[str] = None,
    client_id: Optional[str] = None,
    redirect_uri: Optional[str] = None,
    invitation_email: Optional[str] = None,
    invitation_token: Optional[str] = None,
    error: Optional[str] = None,
    success: Optional[str] = None
) -> HTMLResponse:
    """Render the signup page using Jinja2 template"""
    return templates.TemplateResponse(
        "oidc/signup.html",
        {
            "request": request,
            "client_name": client_name,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "invitation_email": invitation_email,
            "invitation_token": invitation_token,
            "error": error,
            "success": success,
        }
    )


def render_verification_sent_page(request: Request, email: str) -> HTMLResponse:
    """Render email verification sent confirmation page"""
    return templates.TemplateResponse(
        "oidc/verification_sent.html",
        {
            "request": request,
            "email": email,
        }
    )


def render_error_page(
    request: Request,
    title: str = "Something went wrong",
    message: str = "An unexpected error occurred while processing your request.",
    error_code: Optional[str] = None,
    details: Optional[str] = None,
    retry_url: Optional[str] = None,
    back_url: Optional[str] = None,
    status_code: int = 400
) -> HTMLResponse:
    """
    Render a user-friendly error page for OAuth errors.
    
    Args:
        title: Error page title
        message: User-friendly error description
        error_code: Technical error code (e.g., 'invalid_client', 'invalid_request')
        details: Technical details (shown in collapsible section)
        retry_url: URL to retry the action
        back_url: URL to go back
        status_code: HTTP status code for the response
    """
    return templates.TemplateResponse(
        "oidc/error.html",
        {
            "request": request,
            "title": title,
            "message": message,
            "error_code": error_code,
            "details": details,
            "retry_url": retry_url,
            "back_url": back_url,
        },
        status_code=status_code
    )


def _build_invitation_email_html(
    *,
    recipient_name: str,
    inviter_name: str,
    organization_name: str,
    role: str,
    accept_url: str,
    expires_at: str,
    client_name: Optional[str] = None,
) -> str:
    return templates.get_template("onboarding/invitation.html").render(
        recipient_name=recipient_name,
        inviter_name=inviter_name,
        organization_name=organization_name,
        role=role,
        client_name=client_name,
        accept_url=accept_url,
        expires_at=expires_at,
        app_name=APP_NAME,
        year=datetime.now().year,
    )
