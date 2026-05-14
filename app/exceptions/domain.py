from typing import Iterable

from app.core.responses import ErrorDetail


class AppError(Exception):
    def __init__(
        self,
        message: str,
        *,
        code: str,
        status_code: int,
        details: Iterable[ErrorDetail] | None = None,
    ) -> None:
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = list(details) if details else None
        super().__init__(message)


class BusinessValidationError(AppError):
    def __init__(self, message: str, *, details: Iterable[ErrorDetail] | None = None) -> None:
        super().__init__(
            message,
            code="BUSINESS_VALIDATION_ERROR",
            status_code=400,
            details=details,
        )


class AuthenticationError(AppError):
    def __init__(self, message: str = "Authentication required") -> None:
        super().__init__(message, code="UNAUTHORIZED", status_code=401)


class AuthorizationError(AppError):
    def __init__(self, message: str = "Access denied") -> None:
        super().__init__(message, code="FORBIDDEN", status_code=403)


class NotFoundError(AppError):
    def __init__(self, message: str = "Resource not found") -> None:
        super().__init__(message, code="NOT_FOUND", status_code=404)


class ConflictError(AppError):
    def __init__(self, message: str = "Conflict") -> None:
        super().__init__(message, code="CONFLICT", status_code=409)


class RateLimitError(AppError):
    def __init__(self, message: str = "Rate limit exceeded") -> None:
        super().__init__(message, code="RATE_LIMITED", status_code=429)


class UpstreamError(AppError):
    def __init__(self, message: str = "Upstream service error", *, status_code: int = 503) -> None:
        super().__init__(message, code="UPSTREAM_ERROR", status_code=status_code)


class InternalAppError(AppError):
    def __init__(self, message: str = "Internal server error") -> None:
        super().__init__(message, code="INTERNAL_ERROR", status_code=500)
