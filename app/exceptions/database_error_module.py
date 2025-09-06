from enum import Enum
from typing import Type, Dict, Callable, Any
from functools import wraps

import httpx
from fastapi import status, Request
from fastapi.responses import JSONResponse, Response
from asyncpg.exceptions import (
    ConnectionDoesNotExistError,
    ConnectionFailureError,
    PostgresError,
    InterfaceError,
    InvalidCatalogNameError,
    InvalidSchemaNameError,
    FeatureNotSupportedError
)
from pydantic import ValidationError


class DatabaseErrorCode(Enum):
    """Standardized error codes for database operations"""
    CONNECTION_ERROR = "DB_CONNECTION_ERROR"
    OPERATION_ERROR = "DB_OPERATION_ERROR"
    VALIDATION_ERROR = "DB_VALIDATION_ERROR"
    CONFIG_ERROR = "DB_CONFIG_ERROR"
    UNKNOWN_ERROR = "DB_UNKNOWN_ERROR"
    EXTERNAL_API_ERROR = "EXTERNAL_API_ERROR"


class DatabaseError(Exception):
    """Custom database exception with error code and message"""
    def __init__(
            self, error_code: DatabaseErrorCode, message: str, status_code: int
    ):
        self.error_code = error_code
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


# Exception mapping with custom error details
EXCEPTION_MAPPING: Dict[Type[Exception], tuple[DatabaseErrorCode, str, int]] = {
    ConnectionDoesNotExistError: (
        DatabaseErrorCode.CONNECTION_ERROR,
        "Connection to the database does not exist",
        status.HTTP_503_SERVICE_UNAVAILABLE
    ),
    ConnectionFailureError: (
        DatabaseErrorCode.CONNECTION_ERROR,
        "Failed to connect to the database",
        status.HTTP_503_SERVICE_UNAVAILABLE
    ),
    PostgresError: (
        DatabaseErrorCode.OPERATION_ERROR,
        "Database operation failed",
        status.HTTP_400_BAD_REQUEST
    ),
    InterfaceError: (
        DatabaseErrorCode.OPERATION_ERROR,
        "Invalid database operation",
        status.HTTP_400_BAD_REQUEST
    ),
    InvalidCatalogNameError: (
        DatabaseErrorCode.CONFIG_ERROR,
        "Invalid database name",
        status.HTTP_500_INTERNAL_SERVER_ERROR
    ),
    InvalidSchemaNameError: (
        DatabaseErrorCode.CONFIG_ERROR,
        "Invalid schema name",
        status.HTTP_500_INTERNAL_SERVER_ERROR
    ),
    FeatureNotSupportedError: (
        DatabaseErrorCode.CONFIG_ERROR,
        "Feature not supported by the database",
        status.HTTP_500_INTERNAL_SERVER_ERROR
    ),
    ValidationError: (
        DatabaseErrorCode.VALIDATION_ERROR,
        "Invalid data format",
        status.HTTP_422_UNPROCESSABLE_ENTITY
    ),
    httpx.RequestError: (
        DatabaseErrorCode.EXTERNAL_API_ERROR,
        "Failed to communicate with external API",
        status.HTTP_503_SERVICE_UNAVAILABLE
    )
}


def handle_database_exceptions(func: Callable) -> Callable:
    """Decorator to handle database exceptions in a standardized way"""
    @wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return await func(*args, **kwargs)
        except tuple(EXCEPTION_MAPPING.keys()) as e:
            error_code, message, status_code = EXCEPTION_MAPPING[type(e)]
            # Include original error message for more detail
            detailed_message = f"{message}: {str(e)}"
            raise DatabaseError(error_code, detailed_message, status_code)
        except httpx.HTTPStatusError as e:
            # Handle HTTP errors from external API (e.g., 500 from Server A)
            raise DatabaseError(
                DatabaseErrorCode.EXTERNAL_API_ERROR,
                f"External API error: {e.response.status_code} - {e.response.text}",
                e.response.status_code  # Propagate the original status code
            )
        except Exception as e:
            # Handle unexpected exceptions
            logger.info("Unexpected error", exc_info=True)
            raise DatabaseError(
                DatabaseErrorCode.UNKNOWN_ERROR,
                f"An unexpected error occurred: {str(e)}",
                status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    return wrapper


# FastAPI exception handler
def database_exception_handler(
    request: Request, exc: Exception
) -> Response:
    # Type check to ensure we're handling DatabaseError
    if isinstance(exc, DatabaseError):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error_code": exc.error_code.value,
                "message": exc.message,
                "status_code": exc.status_code,
            }
        )
    raise exc  # Re-raise if it's not a DatabaseError