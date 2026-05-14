from dataclasses import dataclass, field
from pydantic.dataclasses import dataclass as pydantic_dataclass
from pydantic import Field
from datetime import datetime, timezone
from typing import Any, Optional, List, TypeVar, Generic

import orjson
from fastapi import status
from fastapi.responses import JSONResponse


class OrjsonResponse(JSONResponse):
    """High-performance JSON response using orjson with native dataclass support."""
    media_type = "application/json"
    
    def render(self, content: Any) -> bytes:
        return orjson.dumps(
            content,
            option=orjson.OPT_SERIALIZE_NUMPY | orjson.OPT_UTC_Z | orjson.OPT_SERIALIZE_DATACLASS
        )


# Helper for timestamp
def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

T = TypeVar("T")


@pydantic_dataclass(slots=True)
class APIResponse(Generic[T]):
    """Standard API response wrapper."""
    success: bool = True
    data: Optional[T] = None
    message: Optional[str] = None
    timestamp: Optional[str] = Field(default_factory=_now)
    
    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"success": self.success, "timestamp": self.timestamp}
        if self.data is not None:
            result["data"] = self.data
        if self.message is not None:
            result["message"] = self.message
        return result


@dataclass(slots=True)
class PaginationMeta:
    """Pagination metadata."""
    page: int = 1
    page_size: int = 20
    total_items: int = 0
    total_pages: int = 0
    
    @classmethod
    def create(cls, page: int, page_size: int, total_items: int) -> "PaginationMeta":
        total_pages = (total_items + page_size - 1) // page_size if page_size > 0 else 0
        return cls(page=page, page_size=page_size, total_items=total_items, total_pages=total_pages)


@dataclass(slots=True)
class PaginatedResponse:
    """Paginated list response."""
    data: List[Any] = field(default_factory=list)
    pagination: PaginationMeta = field(default_factory=PaginationMeta)
    success: bool = True
    timestamp: str = field(default_factory=_now)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "data": self.data,
            "pagination":  self.pagination,
            "timestamp": self.timestamp
        }


@dataclass(slots=True)
class ErrorDetail:
    """Detailed error information."""
    code: str
    message: str
    field: Optional[str] = None


@dataclass(slots=True)
class ErrorBody:
    """Error body with code, message, and optional details."""
    code: str
    message: str
    status: int
    details: Optional[List[ErrorDetail]] = None
    
    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
            "status": self.status,
        }
        if self.details:
            result["details"] = [d for d in self.details]
        return result


@dataclass(slots=True)
class ErrorResponse:
    error: ErrorBody
    success: bool = False
    timestamp: str = field(default_factory=_now)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "error": self.error.to_dict(),
            "timestamp": self.timestamp
        }


def success_response(
    data: Any = None,
    message: Optional[str] = None,
    status_code: int = status.HTTP_200_OK
) -> OrjsonResponse:
    """Create a successful response."""
    response = APIResponse(success=True, data=data, message=message)
    return OrjsonResponse(content=response, status_code=status_code)


def created_response(
    data: Any = None,
    message: str = "Resource created successfully"
) -> OrjsonResponse:
    return success_response(data, message, status.HTTP_201_CREATED)


def no_content_response() -> OrjsonResponse:
    return OrjsonResponse(content=None, status_code=status.HTTP_204_NO_CONTENT)


def paginated_response(
    data: List[Any],
    page: int,
    page_size: int,
    total_items: int
) -> OrjsonResponse:
    """Create a paginated list response."""
    response = PaginatedResponse(
        data=data,
        pagination=PaginationMeta.create(page, page_size, total_items)
    )
    return OrjsonResponse(content=response, status_code=status.HTTP_200_OK)


def error_response(
    code: str,
    message: str,
    status_code: int = status.HTTP_400_BAD_REQUEST,
    details: Optional[List[ErrorDetail]] = None,
    headers: Optional[dict[str, str]] = None,
) -> OrjsonResponse:
    response = ErrorResponse(
        error=ErrorBody(code=code, message=message, status=status_code, details=details)
    )
    return OrjsonResponse(content=response, status_code=status_code, headers=headers)


def validation_error_response(
    message: str = "Request validation failed",
    details: Optional[List[ErrorDetail]] = None
) -> OrjsonResponse:
    """Create a 422 request validation error response."""
    return error_response(
        code="REQUEST_VALIDATION_ERROR",
        message=message,
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        details=details
    )


def not_found_response(
    message: str = "Resource not found",
    resource: Optional[str] = None
) -> OrjsonResponse:
    msg = f"{resource} not found" if resource else message
    return error_response(code="NOT_FOUND", message=msg, status_code=status.HTTP_404_NOT_FOUND)


def unauthorized_response(message: str = "Authentication required") -> OrjsonResponse:
    return error_response(code="UNAUTHORIZED", message=message, status_code=status.HTTP_401_UNAUTHORIZED)


def forbidden_response(message: str = "Access denied") -> OrjsonResponse:
    return error_response(code="FORBIDDEN", message=message, status_code=status.HTTP_403_FORBIDDEN)


def server_error_response(message: str = "Internal server error") -> OrjsonResponse:
    return error_response(code="INTERNAL_ERROR", message=message, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
