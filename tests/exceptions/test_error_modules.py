"""
Tests for app/exceptions/ - Error handling modules.
"""
import pytest
from unittest.mock import MagicMock, AsyncMock
from fastapi import Request
from fastapi.responses import Response
import asyncpg

from app.exceptions.database_error_module import (
    DatabaseError,
    DatabaseErrorCode,
    database_exception_handler,
    handle_database_exceptions
)
from app.exceptions.http_error_module import (
    HTTPError,
    ErrorCode,
    http_exception_handler,
    handle_http_exceptions
)


class TestDatabaseError:
    """Tests for DatabaseError exception."""
    
    def test_database_error_creation(self):
        """Test creating a DatabaseError."""
        error = DatabaseError(
            error_code=DatabaseErrorCode.CONNECTION_ERROR,
            message="Connection failed",
            status_code=500
        )
        
        assert error.message == "Connection failed"
        assert error.status_code == 500
        assert error.error_code == DatabaseErrorCode.CONNECTION_ERROR
    
    def test_database_error_str(self):
        """Test DatabaseError string representation."""
        error = DatabaseError(
            error_code=DatabaseErrorCode.OPERATION_ERROR,
            message="Test error",
            status_code=500
        )
        
        assert str(error) == "Test error"


class TestDatabaseExceptionHandler:
    """Tests for database exception handler."""
    
    def test_database_exception_handler(self):
        """Test database exception handler returns proper response."""
        mock_request = MagicMock()
        mock_request.url = "http://localhost/test"
        mock_request.method = "GET"
        
        error = DatabaseError(
            error_code=DatabaseErrorCode.OPERATION_ERROR,
            message="Query failed",
            status_code=500
        )
        
        response = database_exception_handler(mock_request, error)
        
        assert isinstance(response, Response)
        assert response.status_code == 500


class TestHandleDatabaseExceptionsDecorator:
    """Tests for handle_database_exceptions decorator."""
    
    @pytest.mark.asyncio
    async def test_decorator_passes_through_success(self):
        """Test decorator passes through successful execution."""
        @handle_database_exceptions
        async def successful_func():
            return {"result": "success"}
        
        result = await successful_func()
        
        assert result == {"result": "success"}
    
    @pytest.mark.asyncio
    async def test_decorator_catches_unique_violation(self):
        """Test decorator catches unique violation errors."""
        @handle_database_exceptions
        async def unique_violation_func():
            error = asyncpg.UniqueViolationError("Duplicate key")
            raise error
        
        with pytest.raises(DatabaseError) as exc_info:
            await unique_violation_func()
        
        assert exc_info.value.status_code == 409
    
    @pytest.mark.asyncio
    async def test_decorator_catches_foreign_key_violation(self):
        """Test decorator catches foreign key violation errors."""
        @handle_database_exceptions
        async def fk_violation_func():
            error = asyncpg.ForeignKeyViolationError("FK constraint")
            raise error
        
        with pytest.raises(DatabaseError) as exc_info:
            await fk_violation_func()
        
        assert exc_info.value.status_code == 409


class TestHTTPError:
    """Tests for HTTPError exception."""
    
    def test_http_error_creation(self):
        """Test creating an HTTPError."""
        error = HTTPError(
            error_code=ErrorCode.AUTHENTICATION_ERROR,
            message="Not authorized",
            status_code=401
        )
        
        assert error.message == "Not authorized"
        assert error.status_code == 401
        assert error.error_code == ErrorCode.AUTHENTICATION_ERROR
    
    def test_http_error_str(self):
        """Test HTTPError string representation."""
        error = HTTPError(
            error_code=ErrorCode.CLIENT_ERROR,
            message="Bad request",
            status_code=400
        )
        
        assert str(error) == "Bad request"


class TestHTTPExceptionHandler:
    """Tests for HTTP exception handler."""
    
    def test_http_exception_handler(self):
        """Test HTTP exception handler returns proper response."""
        mock_request = MagicMock()
        mock_request.url = "http://localhost/test"
        mock_request.method = "POST"
        
        error = HTTPError(
            error_code=ErrorCode.VALIDATION_ERROR,
            message="Bad request",
            status_code=400
        )
        
        response = http_exception_handler(mock_request, error)
        
        assert isinstance(response, Response)
        assert response.status_code == 400


class TestHandleHTTPExceptionsDecorator:
    """Tests for handle_http_exceptions decorator."""
    
    @pytest.mark.asyncio
    async def test_decorator_passes_through_success(self):
        """Test decorator passes through successful execution."""
        @handle_http_exceptions
        async def successful_func():
            return {"data": "test"}
        
        result = await successful_func()
        
        assert result == {"data": "test"}
    
    @pytest.mark.asyncio
    async def test_decorator_catches_value_error(self):
        """Test decorator catches ValueError."""
        @handle_http_exceptions
        async def value_error_func():
            raise ValueError("Invalid value")
        
        with pytest.raises(HTTPError) as exc_info:
            await value_error_func()
        
        assert exc_info.value.status_code == 400
