import logging
from typing import Any

import asyncpg
import httpx
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import Response

from app.core.error_pages import render_html_error, wants_html
from app.core.responses import ErrorDetail, error_response
from app.exceptions.domain import (
    AppError,
    AuthenticationError,
    AuthorizationError,
    BusinessValidationError,
    ConflictError,
    InternalAppError,
    NotFoundError,
    RateLimitError,
    UpstreamError,
)

logger = logging.getLogger(__name__)


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, app_error_handler)
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, request_validation_exception_handler)
    app.add_exception_handler(asyncpg.PostgresError, postgres_exception_handler)
    app.add_exception_handler(asyncpg.InterfaceError, postgres_exception_handler)
    app.add_exception_handler(httpx.RequestError, httpx_request_exception_handler)
    app.add_exception_handler(httpx.HTTPStatusError, httpx_status_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)


def _render_error_response(
    request: Request,
    *,
    code: str,
    message: str,
    status_code: int,
    details: list[ErrorDetail] | None = None,
    html_title: str | None = None,
    headers: dict[str, str] | None = None,
) -> Response:
    if wants_html(request):
        return render_html_error(
            request=request,
            title=html_title or message,
            message=message,
            status_code=status_code,
            error_code=code,
        )
    return error_response(
        code=code,
        message=message,
        status_code=status_code,
        details=details,
        headers=headers,
    )


def _coerce_http_exception(exc: HTTPException) -> AppError:
    detail = exc.detail if isinstance(exc.detail, str) else "Request failed"

    if exc.status_code == status.HTTP_400_BAD_REQUEST:
        return BusinessValidationError(detail)
    if exc.status_code == status.HTTP_401_UNAUTHORIZED:
        return AuthenticationError(detail)
    if exc.status_code == status.HTTP_403_FORBIDDEN:
        return AuthorizationError(detail)
    if exc.status_code == status.HTTP_404_NOT_FOUND:
        return NotFoundError(detail)
    if exc.status_code == status.HTTP_409_CONFLICT:
        return ConflictError(detail)
    if exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
        return RateLimitError(detail)
    if 400 <= exc.status_code < 500:
        return AppError(detail, code="CLIENT_ERROR", status_code=exc.status_code)
    return InternalAppError()


def _coerce_database_exception(exc: Exception) -> AppError:
    if isinstance(exc, asyncpg.UniqueViolationError):
        return ConflictError("A record with these values already exists.")
    if isinstance(exc, asyncpg.ForeignKeyViolationError):
        return ConflictError("The request references a record that does not exist.")
    if isinstance(exc, (asyncpg.NotNullViolationError, asyncpg.DataError, asyncpg.InterfaceError)):
        return BusinessValidationError("The request contains invalid data.")
    if isinstance(exc, asyncpg.InsufficientPrivilegeError):
        return AuthorizationError("Database operation is not permitted.")
    return InternalAppError("An error occurred while processing your request. Please try again later.")


def _coerce_httpx_status_error(exc: httpx.HTTPStatusError) -> AppError:
    status_code = exc.response.status_code
    if status_code == status.HTTP_401_UNAUTHORIZED:
        return AuthenticationError("Authentication required")
    if status_code == status.HTTP_403_FORBIDDEN:
        return AuthorizationError("Access forbidden")
    if status_code == status.HTTP_404_NOT_FOUND:
        return NotFoundError("Upstream resource not found")
    if status_code == status.HTTP_409_CONFLICT:
        return ConflictError("Upstream service reported a conflict")
    if status_code == status.HTTP_429_TOO_MANY_REQUESTS:
        return RateLimitError()
    if 400 <= status_code < 500:
        return BusinessValidationError("Upstream service rejected the request.")
    return UpstreamError(status_code=status_code)


async def app_error_handler(request: Request, exc: AppError) -> Response:
    logger.error(
        "Application error",
        extra={
            "path": str(request.url),
            "method": request.method,
            "status_code": exc.status_code,
            "code": exc.code,
            "error_message": exc.message,
        },
    )
    return _render_error_response(
        request,
        code=exc.code,
        message=exc.message,
        status_code=exc.status_code,
        details=exc.details,
    )


async def http_exception_handler(request: Request, exc: HTTPException) -> Response:
    app_error = _coerce_http_exception(exc)
    headers = {"WWW-Authenticate": "Bearer"} if exc.status_code == status.HTTP_401_UNAUTHORIZED else None
    return _render_error_response(
        request,
        code=app_error.code,
        message=app_error.message,
        status_code=app_error.status_code,
        details=app_error.details,
        headers=headers,
    )


async def request_validation_exception_handler(request: Request, exc: RequestValidationError) -> Response:
    details = [
        ErrorDetail(
            code=error["type"],
            field=".".join(str(part) for part in error["loc"] if part != "body") or None,
            message=error["msg"],
        )
        for error in exc.errors()
    ]
    logger.error(
        "Request validation error",
        extra={
            "path": str(request.url),
            "method": request.method,
            "status_code": status.HTTP_422_UNPROCESSABLE_ENTITY,
            "errors": exc.errors(),
        },
    )
    return _render_error_response(
        request,
        code="REQUEST_VALIDATION_ERROR",
        message="Request validation failed",
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        details=details,
        html_title="Validation Error",
    )


async def postgres_exception_handler(request: Request, exc: Exception) -> Response:
    logger.exception(
        "Database exception",
        extra={
            "path": str(request.url),
            "method": request.method,
        },
    )
    app_error = _coerce_database_exception(exc)
    return _render_error_response(
        request,
        code=app_error.code,
        message=app_error.message,
        status_code=app_error.status_code,
        details=app_error.details,
        html_title="Database Error",
    )


async def httpx_request_exception_handler(request: Request, exc: httpx.RequestError) -> Response:
    logger.exception(
        "Upstream request exception",
        extra={
            "path": str(request.url),
            "method": request.method,
        },
    )
    status_code = status.HTTP_504_GATEWAY_TIMEOUT if isinstance(exc, httpx.TimeoutException) else status.HTTP_503_SERVICE_UNAVAILABLE
    app_error = UpstreamError("Failed to communicate with an upstream service.", status_code=status_code)
    return _render_error_response(
        request,
        code=app_error.code,
        message=app_error.message,
        status_code=app_error.status_code,
    )


async def httpx_status_exception_handler(request: Request, exc: httpx.HTTPStatusError) -> Response:
    logger.exception(
        "Upstream status exception",
        extra={
            "path": str(request.url),
            "method": request.method,
            "upstream_status": exc.response.status_code,
        },
    )
    app_error = _coerce_httpx_status_error(exc)
    return _render_error_response(
        request,
        code=app_error.code,
        message=app_error.message,
        status_code=app_error.status_code,
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> Response:
    logger.exception(
        "Unhandled exception",
        extra={
            "path": str(request.url),
            "method": request.method,
            "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
        },
    )
    return _render_error_response(
        request,
        code="INTERNAL_ERROR",
        message="Internal server error",
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        html_title="Internal Server Error",
    )
