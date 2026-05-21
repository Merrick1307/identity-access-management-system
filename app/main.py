from pathlib import Path
import logging

import jwt
import uvicorn
from fastapi import FastAPI, status, Request
from fastapi.templating import Jinja2Templates
from starlette.middleware.cors import CORSMiddleware

from app.api import api_router

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
from app.audit_logs import AuditLoggingMiddleware
from app.core.responses import OrjsonResponse, error_response
from app.database import lifespan
from app.exceptions.handlers import register_exception_handlers
from app.core.error_pages import wants_html, render_html_error

logger = logging.getLogger(__name__)

app: FastAPI = FastAPI(
    title="HEX IAM",
    description="Policy-Embedded Identity & Access Management System",
    version="0.2.0",
    lifespan=lifespan,
    default_response_class=OrjsonResponse
)


app.include_router(api_router, prefix="/api")


def _unauthorized_response(request: Request, detail: str):
    """Return a 401 response (HTML for browsers, JSON for APIs)."""
    if wants_html(request):
        return render_html_error(
            request=request,
            title="Authentication Required",
            message=detail,
            status_code=status.HTTP_401_UNAUTHORIZED,
            error_code="UNAUTHORIZED",
        )
    return error_response(
        code="UNAUTHORIZED",
        message=detail,
        status_code=status.HTTP_401_UNAUTHORIZED,
        headers={"WWW-Authenticate": "Bearer"}
    )


def _bad_request_response(request: Request, detail: str):
    """Return a 400 response (HTML for browsers, JSON for APIs)."""
    if wants_html(request):
        return render_html_error(
            request=request,
            title="Bad Request",
            message=detail,
            status_code=status.HTTP_400_BAD_REQUEST,
            error_code="BAD_REQUEST",
        )
    return error_response(
        code="BAD_REQUEST",
        message=detail,
        status_code=status.HTTP_400_BAD_REQUEST,
    )

@app.get("/health")
def health_check():
    return {"status": "ok"}


PUBLIC_PATHS = {
  "/docs", "/openapi.json", "/health", "/favicon.ico",
  "/api/v1/onboarding/tenant", "/api/v1/onboarding/tenant/",
}
PUBLIC_PREFIXES = (
  "/api/v1/oidc/authorize", "/api/v1/oidc/login", "/api/v1/oidc/consent",
  "/api/v1/oidc/token", "/api/v1/oidc/signup", "/api/v1/oidc/logout",
  "/api/v1/oidc/federation/callback",
  "/api/v1/oidc/jwks", "/api/v1/oidc/userinfo", "/api/v1/oidc/introspect",
  "/api/v1/.well-known/openid-configuration", "/api/v1/onboarding/email/verify"
)

@app.middleware("http")
async def middle_ware(request: Request, call_next):
    path = request.scope["path"]
    if path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES) or path.endswith("/token"):
        return await call_next(request)

    token_header = request.headers.get("Authorization")

    if not token_header or not token_header.startswith("Bearer "):
        return _unauthorized_response(request, "Could not validate credentials")

    token = token_header.split(" ")[-1]

    if not token:
        return _bad_request_response(request, "Unable to get authorization token")

    try:
        token_header_jti = jwt.get_unverified_header(token).get("jti")
    except jwt.InvalidTokenError:
        return _unauthorized_response(request, "Invalid token format")

    if not token_header_jti:
        return _unauthorized_response(request, "Token missing JTI")

    if token_header_jti in request.app.state.bloom_filter:
        return _unauthorized_response(request, "Token has been revoked")

    return await call_next(request)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)
app.add_middleware(AuditLoggingMiddleware)
register_exception_handlers(app)


if __name__ == '__main__':
    uvicorn.run(
        app="app.main:app",
        host="0.0.0.0",
        port=8000,
        workers=4
    )
