import jwt
import uvicorn
from fastapi import FastAPI, status, Request, HTTPException
from starlette.middleware.cors import CORSMiddleware

from app.api import api_router
from app.audit_logs import AuditLoggingMiddleware
from app.database import lifespan
from app.exceptions.database_error_module import DatabaseError, database_exception_handler
from app.exceptions.http_error_module import http_exception_handler, HTTPError

app: FastAPI = FastAPI(title="HEX IAM", lifespan=lifespan)


app.include_router(api_router, prefix="/api")


@app.middleware("http")
async def middle_ware(request: Request, call_next):
    try:
        if (request.url.path in {"/docs", "/openapi.json", "/health", "/favicon.ico"}
            or request.url.path.endswith(("/token", "/onboarding/tenant/", "/onboarding/email/verify"))):
            response = await call_next(request)
            return response

        token_header = request.headers.get("Authorization")

        if not token_header or not token_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )

        token = token_header.split(" ")[-1]

        if not token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unable to get authorization token"
            )

        token_header_jti = jwt.get_unverified_header(token).get("jti")

        if not token_header_jti:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing JTI"
            )

        if token_header_jti in request.app.state.bloom_filter:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token Revoked"
            )

        return await call_next(request)
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token format"
        )
    except HTTPException:
        raise
    except Exception:
        raise


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)
app.add_middleware(AuditLoggingMiddleware, table_name="audit_logs")
app.add_exception_handler(DatabaseError, database_exception_handler)
app.add_exception_handler(HTTPError, http_exception_handler)


if __name__ == '__main__':
    uvicorn.run(
        app="app.main:app",
        host="0.0.0.0",
        port=8000
    )
