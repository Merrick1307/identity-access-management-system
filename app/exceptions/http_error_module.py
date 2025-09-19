from enum import Enum
from typing import Type, Dict, Callable, Any
from functools import wraps

import httpx
from fastapi import status, Request, HTTPException
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError


class ErrorCode(Enum):
    """Standardized error codes for HTTP operations"""
    CLIENT_ERROR = "CLIENT_ERROR"
    SERVER_ERROR = "SERVER_ERROR"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    NETWORK_ERROR = "NETWORK_ERROR"
    TIMEOUT_ERROR = "TIMEOUT_ERROR"
    AUTHENTICATION_ERROR = "AUTHENTICATION_ERROR"
    AUTHORIZATION_ERROR = "AUTHORIZATION_ERROR"
    RATE_LIMIT_ERROR = "RATE_LIMIT_ERROR"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


class HTTPError(Exception):
    """Custom HTTP exception with error code and message"""

    def __init__(
            self, error_code: ErrorCode, message: str, status_code: int
    ):
        self.error_code = error_code
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


# Exception mapping with custom error details
HTTP_EXCEPTION_MAPPING: Dict[Type[Exception], tuple[ErrorCode, str, int]] = {
    httpx.RequestError: (
        ErrorCode.NETWORK_ERROR,
        "Failed to communicate with server",
        status.HTTP_503_SERVICE_UNAVAILABLE
    ),
    httpx.ConnectError: (
        ErrorCode.NETWORK_ERROR,
        "Failed to establish connection",
        status.HTTP_503_SERVICE_UNAVAILABLE
    ),
    httpx.TimeoutException: (
        ErrorCode.TIMEOUT_ERROR,
        "Request timed out",
        status.HTTP_504_GATEWAY_TIMEOUT
    ),
    httpx.ReadTimeout: (
        ErrorCode.TIMEOUT_ERROR,
        "Read operation timed out",
        status.HTTP_504_GATEWAY_TIMEOUT
    ),
    httpx.WriteTimeout: (
        ErrorCode.TIMEOUT_ERROR,
        "Write operation timed out",
        status.HTTP_504_GATEWAY_TIMEOUT
    ),
    httpx.ConnectTimeout: (
        ErrorCode.TIMEOUT_ERROR,
        "Connection timed out",
        status.HTTP_504_GATEWAY_TIMEOUT
    ),
    httpx.PoolTimeout: (
        ErrorCode.TIMEOUT_ERROR,
        "Connection pool timeout",
        status.HTTP_504_GATEWAY_TIMEOUT
    ),
    ValidationError: (
        ErrorCode.VALIDATION_ERROR,
        "Invalid data format",
        status.HTTP_422_UNPROCESSABLE_ENTITY
    ),
    ValueError: (
        ErrorCode.CLIENT_ERROR,
        "Invalid input value",
        status.HTTP_400_BAD_REQUEST
    ),
    TypeError: (
        ErrorCode.CLIENT_ERROR,
        "Invalid data type",
        status.HTTP_400_BAD_REQUEST
    ),
    KeyError: (
        ErrorCode.CLIENT_ERROR,
        "Missing required field",
        status.HTTP_400_BAD_REQUEST
    ),
    AttributeError: (
        ErrorCode.SERVER_ERROR,
        "Server configuration error",
        status.HTTP_500_INTERNAL_SERVER_ERROR
    )
}


def handle_http_exceptions(func: Callable) -> Callable:
    """Decorator to handle HTTP exceptions in a standardized way"""

    @wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        logger = next((arg for arg in args if arg.__class__.__name__ == 'AuditLogger'), None)
        if not logger:
            logger = next((v for v in kwargs.values() if v.__class__.__name__ == 'AuditLogger'), None)

        try:
            return await func(*args, **kwargs)
        except tuple(HTTP_EXCEPTION_MAPPING.keys()) as e:
            error_code, message, status_code = HTTP_EXCEPTION_MAPPING[type(e)]
            # Include original error message for more detail
            detailed_message = f"{message}: {str(e)}"
            if logger:
                await logger.force_error(f"HTTP Exception: {detailed_message}")
            raise HTTPError(error_code, detailed_message, status_code)
        except httpx.HTTPStatusError as e:
            # Handle HTTP status errors with specific mappings
            if e.response.status_code == 401:
                error_code = ErrorCode.AUTHENTICATION_ERROR
                message = "Authentication required"
            elif e.response.status_code == 403:
                error_code = ErrorCode.AUTHORIZATION_ERROR
                message = "Access forbidden"
            elif e.response.status_code == 429:
                error_code = ErrorCode.RATE_LIMIT_ERROR
                message = "Rate limit exceeded"
            elif 400 <= e.response.status_code < 500:
                error_code = ErrorCode.CLIENT_ERROR
                message = "Client error"
            else:
                error_code = ErrorCode.SERVER_ERROR
                message = "Server error"

            detailed_message = f"{message}: {e.response.status_code} - {e.response.text}"
            if logger:
                await logger.force_error(f"HTTP Status Error: {detailed_message}")
            raise HTTPError(error_code, detailed_message, e.response.status_code)
        except HTTPException as e:
            if logger:
                await logger.force_error(f"FastAPI HTTPException: {e.detail}")
            # Map status code to appropriate error code
            if e.status_code == 401:
                error_code = ErrorCode.AUTHENTICATION_ERROR
            elif e.status_code == 403:
                error_code = ErrorCode.AUTHORIZATION_ERROR
            elif e.status_code == 422:
                error_code = ErrorCode.VALIDATION_ERROR
            elif 400 <= e.status_code < 500:
                error_code = ErrorCode.CLIENT_ERROR
            else:
                error_code = ErrorCode.SERVER_ERROR

            raise HTTPError(error_code, e.detail, e.status_code)
        except Exception as e:
            # Handle unexpected exceptions
            if logger:
                await logger.force_error("Unexpected error", exception_details=str(e))
            raise HTTPError(
                ErrorCode.UNKNOWN_ERROR,
                f"An unexpected error occurred: {str(e)}",
                status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    return wrapper


# FastAPI exception handler
def http_exception_handler(
        request: Request, exc: Exception
) -> Response:
    """Handle HTTP exceptions and return standardized JSON responses"""
    if isinstance(exc, HTTPError):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error_code": exc.error_code.value,
                "message": exc.message,
                "status_code": exc.status_code,
                "path": str(request.url),
                "method": request.method
            }
        )
    elif isinstance(exc, HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                    "code": "HTTP_EXCEPTION",
                    "message": exc.detail,
                    "status_code": exc.status_code,
                    "path": str(request.url),
                    "method": request.method,
            }
        )
    raise exc  # Re-raise if it's not an HTTPError