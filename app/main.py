import uvicorn
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from app.api import api_router
from app.audit_logs import AuditLoggingMiddleware
from app.database import lifespan
from app.exceptions.database_error_module import DatabaseError, database_exception_handler
from app.exceptions.http_error_module import http_exception_handler, HTTPError

app: FastAPI = FastAPI(title="HEX IAM", lifespan=lifespan)


app.include_router(api_router, prefix="/api")

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
