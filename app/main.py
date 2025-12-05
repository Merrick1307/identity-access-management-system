import jwt
import uvicorn
from fastapi import FastAPI, status, Request
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

from app.api import api_router
from app.audit_logs import AuditLoggingMiddleware
from app.core.responses import OrjsonResponse
from app.database import lifespan
from app.exceptions.database_error_module import DatabaseError, database_exception_handler
from app.exceptions.http_error_module import http_exception_handler, HTTPError

app: FastAPI = FastAPI(
    title="HEX IAM",
    description="Policy-Embedded Identity & Access Management System",
    version="0.1.0",
    lifespan=lifespan,
    default_response_class=OrjsonResponse
)


app.include_router(api_router, prefix="/api")


def _unauthorized_response(detail: str) -> JSONResponse:
    """Return a proper 401 JSON response."""
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": detail, "error": {"code": "UNAUTHORIZED", "message": detail}},
        headers={"WWW-Authenticate": "Bearer"}
    )


def _bad_request_response(detail: str) -> JSONResponse:
    """Return a proper 400 JSON response."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": detail, "error": {"code": "BAD_REQUEST", "message": detail}}
    )


@app.middleware("http")
async def middle_ware(request: Request, call_next):
    # Skip auth for public endpoints
    if (request.url.path in {"/docs", "/openapi.json", "/health", "/favicon.ico"}
        or request.url.path.endswith(("/token", "/onboarding/tenant/", "/onboarding/email/verify"))):
        return await call_next(request)

    token_header = request.headers.get("Authorization")

    if not token_header or not token_header.startswith("Bearer "):
        return _unauthorized_response("Could not validate credentials")

    token = token_header.split(" ")[-1]

    if not token:
        return _bad_request_response("Unable to get authorization token")

    try:
        token_header_jti = jwt.get_unverified_header(token).get("jti")
    except jwt.InvalidTokenError:
        return _unauthorized_response("Invalid token format")

    if not token_header_jti:
        return _unauthorized_response("Token missing JTI")

    if token_header_jti in request.app.state.bloom_filter:
        return _unauthorized_response("Token has been revoked")

    return await call_next(request)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)
app.add_middleware(AuditLoggingMiddleware)
app.add_exception_handler(DatabaseError, database_exception_handler)
app.add_exception_handler(HTTPError, http_exception_handler)


if __name__ == '__main__':
    uvicorn.run(
        app="app.main:app",
        host="0.0.0.0",
        port=8000,
        workers=4
    )
