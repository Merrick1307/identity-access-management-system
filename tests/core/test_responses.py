"""
Tests for app/core/responses.py - Response utilities.
"""
import pytest
import orjson
from datetime import datetime, timezone

from app.core.responses import (
    OrjsonResponse,
    APIResponse,
    PaginationMeta,
    PaginatedResponse,
    ErrorDetail,
    ErrorBody,
    ErrorResponse,
    success_response,
    created_response,
    no_content_response,
    paginated_response,
    error_response,
    validation_error_response,
    not_found_response,
    unauthorized_response,
    forbidden_response,
    server_error_response
)


class TestOrjsonResponse:
    """Tests for OrjsonResponse class."""
    
    def test_orjson_response_renders_dict(self):
        """Test that OrjsonResponse correctly renders a dictionary."""
        response = OrjsonResponse(content={"key": "value"})
        body = response.body
        
        assert orjson.loads(body) == {"key": "value"}
    
    def test_orjson_response_renders_nested_structure(self):
        """Test that OrjsonResponse handles nested structures."""
        content = {
            "data": {
                "users": [{"id": 1}, {"id": 2}],
                "count": 2
            }
        }
        response = OrjsonResponse(content=content)
        body = response.body
        
        assert orjson.loads(body) == content
    
    def test_orjson_response_media_type(self):
        """Test that OrjsonResponse has correct media type."""
        response = OrjsonResponse(content={})
        
        assert response.media_type == "application/json"


class TestAPIResponse:
    """Tests for APIResponse dataclass."""
    
    def test_api_response_default_values(self):
        """Test APIResponse with default values."""
        response = APIResponse()
        
        assert response.success is True
        assert response.data is None
        assert response.message is None
        assert response.timestamp is not None
    
    def test_api_response_to_dict(self):
        """Test APIResponse to_dict method."""
        response = APIResponse(
            success=True,
            data={"user": "test"},
            message="Success"
        )
        result = response.to_dict()
        
        assert result["success"] is True
        assert result["data"] == {"user": "test"}
        assert result["message"] == "Success"
        assert "timestamp" in result
    
    def test_api_response_to_dict_excludes_none(self):
        """Test that to_dict excludes None values for data and message."""
        response = APIResponse(success=True)
        result = response.to_dict()
        
        assert "data" not in result
        assert "message" not in result


class TestPaginationMeta:
    """Tests for PaginationMeta dataclass."""
    
    def test_pagination_meta_create(self):
        """Test PaginationMeta.create factory method."""
        meta = PaginationMeta.create(page=2, page_size=10, total_items=45)
        
        assert meta.page == 2
        assert meta.page_size == 10
        assert meta.total_items == 45
        assert meta.total_pages == 5
    
    def test_pagination_meta_create_exact_pages(self):
        """Test PaginationMeta when items divide evenly."""
        meta = PaginationMeta.create(page=1, page_size=10, total_items=30)
        
        assert meta.total_pages == 3
    
    def test_pagination_meta_create_zero_page_size(self):
        """Test PaginationMeta with zero page size."""
        meta = PaginationMeta.create(page=1, page_size=0, total_items=10)
        
        assert meta.total_pages == 0
    
    def test_pagination_meta_create_no_items(self):
        """Test PaginationMeta with no items."""
        meta = PaginationMeta.create(page=1, page_size=10, total_items=0)
        
        assert meta.total_pages == 0


class TestPaginatedResponse:
    """Tests for PaginatedResponse dataclass."""
    
    def test_paginated_response_to_dict(self):
        """Test PaginatedResponse to_dict method."""
        response = PaginatedResponse(
            data=[{"id": 1}, {"id": 2}],
            pagination=PaginationMeta.create(1, 10, 2)
        )
        result = response.to_dict()
        
        assert result["success"] is True
        assert result["data"] == [{"id": 1}, {"id": 2}]
        assert result["pagination"]["page"] == 1
        assert result["pagination"]["total_items"] == 2


class TestErrorClasses:
    """Tests for error-related classes."""
    
    def test_error_detail_creation(self):
        """Test ErrorDetail creation."""
        detail = ErrorDetail(
            code="VALIDATION_ERROR",
            message="Field is required",
            field="email"
        )
        
        assert detail.code == "VALIDATION_ERROR"
        assert detail.message == "Field is required"
        assert detail.field == "email"
    
    def test_error_body_to_dict(self):
        """Test ErrorBody to_dict method."""
        body = ErrorBody(
            code="NOT_FOUND",
            message="User not found",
            path="/api/v1/users/123",
            method="GET"
        )
        result = body.to_dict()
        
        assert result["code"] == "NOT_FOUND"
        assert result["message"] == "User not found"
        assert result["path"] == "/api/v1/users/123"
        assert result["method"] == "GET"
    
    def test_error_body_with_details(self):
        """Test ErrorBody with details list."""
        details = [
            ErrorDetail("REQUIRED", "Field required", "email"),
            ErrorDetail("INVALID", "Invalid format", "phone")
        ]
        body = ErrorBody(
            code="VALIDATION_ERROR",
            message="Validation failed",
            details=details
        )
        result = body.to_dict()
        
        assert len(result["details"]) == 2
    
    def test_error_response_to_dict(self):
        """Test ErrorResponse to_dict method."""
        response = ErrorResponse(
            error=ErrorBody(code="ERROR", message="Something went wrong")
        )
        result = response.to_dict()
        
        assert result["success"] is False
        assert result["error"]["code"] == "ERROR"
        assert "timestamp" in result


class TestResponseFactoryFunctions:
    """Tests for response factory functions."""
    
    def test_success_response_default(self):
        """Test success_response with default values."""
        response = success_response()
        
        assert response.status_code == 200
        body = orjson.loads(response.body)
        assert body["success"] is True
    
    def test_success_response_with_data_and_message(self):
        """Test success_response with data and message."""
        response = success_response(
            data={"user_id": "123"},
            message="User created"
        )
        
        body = orjson.loads(response.body)
        assert body["data"] == {"user_id": "123"}
        assert body["message"] == "User created"
    
    def test_created_response(self):
        """Test created_response."""
        response = created_response(data={"id": "new-123"})
        
        assert response.status_code == 201
        body = orjson.loads(response.body)
        assert body["data"] == {"id": "new-123"}
    
    def test_no_content_response(self):
        """Test no_content_response."""
        response = no_content_response()
        
        assert response.status_code == 204
    
    def test_paginated_response_factory(self):
        """Test paginated_response factory."""
        data = [{"id": 1}, {"id": 2}, {"id": 3}]
        response = paginated_response(data, page=1, page_size=10, total_items=3)
        
        assert response.status_code == 200
        body = orjson.loads(response.body)
        assert body["data"] == data
        assert body["pagination"]["total_items"] == 3
    
    def test_error_response_factory(self):
        """Test error_response factory."""
        response = error_response(
            code="BAD_REQUEST",
            message="Invalid input",
            status_code=400
        )
        
        assert response.status_code == 400
        body = orjson.loads(response.body)
        assert body["error"]["code"] == "BAD_REQUEST"
    
    def test_validation_error_response(self):
        """Test validation_error_response."""
        response = validation_error_response(message="Validation failed")
        
        assert response.status_code == 422
        body = orjson.loads(response.body)
        assert body["error"]["code"] == "VALIDATION_ERROR"
    
    def test_not_found_response_default(self):
        """Test not_found_response with default message."""
        response = not_found_response()
        
        assert response.status_code == 404
        body = orjson.loads(response.body)
        assert body["error"]["code"] == "NOT_FOUND"
    
    def test_not_found_response_with_resource(self):
        """Test not_found_response with resource name."""
        response = not_found_response(resource="User")
        
        body = orjson.loads(response.body)
        assert "User not found" in body["error"]["message"]
    
    def test_unauthorized_response(self):
        """Test unauthorized_response."""
        response = unauthorized_response()
        
        assert response.status_code == 401
        body = orjson.loads(response.body)
        assert body["error"]["code"] == "UNAUTHORIZED"
    
    def test_forbidden_response(self):
        """Test forbidden_response."""
        response = forbidden_response()
        
        assert response.status_code == 403
        body = orjson.loads(response.body)
        assert body["error"]["code"] == "FORBIDDEN"
    
    def test_server_error_response(self):
        """Test server_error_response."""
        response = server_error_response()
        
        assert response.status_code == 500
        body = orjson.loads(response.body)
        assert body["error"]["code"] == "INTERNAL_ERROR"
