"""
Template utilities for OIDC endpoints.
Provides functions to render HTML templates using Jinja2.
"""
from pathlib import Path
from typing import Optional, List

from fastapi import Request
from fastapi.templating import Jinja2Templates
from starlette.responses import HTMLResponse

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
