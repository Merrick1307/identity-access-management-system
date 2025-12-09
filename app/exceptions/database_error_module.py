from enum import Enum
from typing import Type, Dict, Callable, Any
from functools import wraps

import httpx
from fastapi import status, Request
from fastapi.responses import Response
from asyncpg.exceptions import (
    # Connection Errors
    ConnectionDoesNotExistError,
    ConnectionFailureError,

    # Data Errors
    DataError,
    NumericValueOutOfRangeError,
    StringDataRightTruncationError,

    # Integrity Errors
    UniqueViolationError,
    ForeignKeyViolationError,
    NotNullViolationError,
    CheckViolationError,
    ExclusionViolationError,

    # Authorization Errors
    InsufficientPrivilegeError,
    InvalidAuthorizationSpecificationError,

    # Transaction Errors
    DeadlockDetectedError,

    # SQL/Syntax Errors
    UndefinedColumnError,
    UndefinedTableError,
    UndefinedFunctionError,

    # Schema/Catalog Errors
    InvalidCatalogNameError,
    InvalidSchemaNameError,

    # Feature Errors
    FeatureNotSupportedError,

    # General
    PostgresError,
    InterfaceError,
)
from pydantic import ValidationError

from app.core.responses import error_response


class DatabaseErrorCode(Enum):
    """Standardized error codes for database operations"""
    CONNECTION_ERROR = "DB_CONNECTION_ERROR"
    OPERATION_ERROR = "DB_OPERATION_ERROR"
    VALIDATION_ERROR = "DB_VALIDATION_ERROR"
    INTEGRITY_ERROR = "DB_INTEGRITY_ERROR"
    PERMISSION_ERROR = "DB_PERMISSION_ERROR"
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

    # Data Errors (400)
    DataError: (
        DatabaseErrorCode.VALIDATION_ERROR,
        "Invalid data format or value",
        status.HTTP_400_BAD_REQUEST
    ),
    NumericValueOutOfRangeError: (
        DatabaseErrorCode.VALIDATION_ERROR,
        "Numeric value is out of range",
        status.HTTP_400_BAD_REQUEST
    ),
    StringDataRightTruncationError: (
        DatabaseErrorCode.VALIDATION_ERROR,
        "String data is too long",
        status.HTTP_400_BAD_REQUEST
    ),

    # Integrity Errors (409)
    UniqueViolationError: (
        DatabaseErrorCode.INTEGRITY_ERROR,
        "Value already exists (unique constraint)",
        status.HTTP_409_CONFLICT
    ),
    ForeignKeyViolationError: (
        DatabaseErrorCode.INTEGRITY_ERROR,
        "Referenced record does not exist",
        status.HTTP_409_CONFLICT
    ),
    NotNullViolationError: (
        DatabaseErrorCode.INTEGRITY_ERROR,
        "Required field cannot be null",
        status.HTTP_400_BAD_REQUEST
    ),
    CheckViolationError: (
        DatabaseErrorCode.INTEGRITY_ERROR,
        "Value violates check constraint",
        status.HTTP_409_CONFLICT
    ),
    ExclusionViolationError: (
        DatabaseErrorCode.INTEGRITY_ERROR,
        "Value violates exclusion constraint",
        status.HTTP_409_CONFLICT
    ),

    # Authorization Errors (403)
    InsufficientPrivilegeError: (
        DatabaseErrorCode.PERMISSION_ERROR,
        "Insufficient permissions for this operation",
        status.HTTP_403_FORBIDDEN
    ),
    InvalidAuthorizationSpecificationError: (
        DatabaseErrorCode.PERMISSION_ERROR,
        "Invalid authorization specification",
        status.HTTP_403_FORBIDDEN
    ),
    DeadlockDetectedError: (
        DatabaseErrorCode.OPERATION_ERROR,
        "Database deadlock detected - please retry",
        status.HTTP_409_CONFLICT
    ),

    # SQL/Syntax Errors (400)
    SyntaxError: (
        DatabaseErrorCode.CONFIG_ERROR,
        "SQL syntax error (server-side issue)",
        status.HTTP_500_INTERNAL_SERVER_ERROR
    ),
    UndefinedColumnError: (
        DatabaseErrorCode.CONFIG_ERROR,
        "Column does not exist (server-side issue)",
        status.HTTP_500_INTERNAL_SERVER_ERROR
    ),
    UndefinedTableError: (
        DatabaseErrorCode.CONFIG_ERROR,
        "Table does not exist (server-side issue)",
        status.HTTP_500_INTERNAL_SERVER_ERROR
    ),
    UndefinedFunctionError: (
        DatabaseErrorCode.CONFIG_ERROR,
        "Function does not exist (server-side issue)",
        status.HTTP_500_INTERNAL_SERVER_ERROR
    ),

    # Schema/Catalog Errors (500)
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

    # Feature Errors (500)
    FeatureNotSupportedError: (
        DatabaseErrorCode.CONFIG_ERROR,
        "Feature not supported by the database",
        status.HTTP_500_INTERNAL_SERVER_ERROR
    ),

    # Validation (422)
    ValidationError: (
        DatabaseErrorCode.VALIDATION_ERROR,
        "Invalid data format",
        status.HTTP_422_UNPROCESSABLE_ENTITY
    ),

    # Generic fallback (500)
    PostgresError: (
        DatabaseErrorCode.OPERATION_ERROR,
        "Database operation failed",
        status.HTTP_500_INTERNAL_SERVER_ERROR
    ),
    InterfaceError: (
        DatabaseErrorCode.OPERATION_ERROR,
        "Invalid database operation",
        status.HTTP_400_BAD_REQUEST
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
        logger = next((arg for arg in args if hasattr(arg, 'force_error')), None)
        if not logger:
            logger = next((v for v in kwargs.values() if hasattr(v, 'force_error')), None)

        try:
            return await func(*args, **kwargs)
        except tuple(EXCEPTION_MAPPING.keys()) as e:
            error_code, message, status_code = EXCEPTION_MAPPING[type(e)]
            detailed_message = f"{message}: {str(e)}"
            if logger:
                await logger.force_error(f"Database Exception: {detailed_message}", exception_details=str(e))
            raise DatabaseError(error_code, detailed_message, status_code)

        except httpx.HTTPStatusError as e:
            detailed_message = f"External API error: {e.response.status_code} - {e.response.text}"
            if logger:
                await logger.force_error(f"External API Error: {detailed_message}", exception_details=str(e))
            raise DatabaseError(
                DatabaseErrorCode.EXTERNAL_API_ERROR,
                detailed_message,
                e.response.status_code
            )

        except Exception as e:
            if logger:
                await logger.force_error("Unexpected database error", exception_details=str(e))
            raise DatabaseError(
                DatabaseErrorCode.UNKNOWN_ERROR,
                f"An unexpected error occurred: {str(e)}",
                status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    return wrapper


def database_exception_handler(request: Request, exc: Exception) -> Response:
    """Handle database exceptions and return standardized responses"""
    if isinstance(exc, DatabaseError):
        return error_response(
            code=exc.error_code.value,
            message=exc.message,
            status_code=exc.status_code,
            path=str(request.url),
            method=request.method
        )
    raise exc
