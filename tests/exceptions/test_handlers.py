import orjson
import pytest
import httpx
import asyncpg
from fastapi import HTTPException
from fastapi.exceptions import RequestValidationError
from starlette.requests import Request

from app.exceptions.domain import BusinessValidationError, ConflictError
from app.exceptions.handlers import (
    app_error_handler,
    http_exception_handler,
    request_validation_exception_handler,
    postgres_exception_handler,
    httpx_request_exception_handler,
)


def make_request(path: str = "/test", method: str = "GET") -> Request:
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": [(b"accept", b"application/json")],
        "query_string": b"",
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 1234),
    }
    return Request(scope)


def json_body(response) -> dict:
    return orjson.loads(response.body)


@pytest.mark.asyncio
async def test_app_error_handler_uses_uniform_schema():
    response = await app_error_handler(
        make_request(),
        BusinessValidationError("Invalid business rule"),
    )

    body = json_body(response)
    assert response.status_code == 400
    assert body["success"] is False
    assert body["error"]["code"] == "BUSINESS_VALIDATION_ERROR"
    assert body["error"]["message"] == "Invalid business rule"
    assert body["error"]["status"] == 400


@pytest.mark.asyncio
async def test_http_exception_handler_maps_unauthorized_and_header():
    response = await http_exception_handler(
        make_request(),
        HTTPException(status_code=401, detail="Missing token"),
    )

    body = json_body(response)
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert body["error"]["code"] == "UNAUTHORIZED"
    assert body["error"]["status"] == 401


@pytest.mark.asyncio
async def test_request_validation_exception_handler_returns_uniform_schema():
    exc = RequestValidationError(
        [{"type": "missing", "loc": ("body", "email"), "msg": "Field required", "input": {}}]
    )

    response = await request_validation_exception_handler(make_request(method="POST"), exc)

    body = json_body(response)
    assert response.status_code == 422
    assert body["error"]["code"] == "REQUEST_VALIDATION_ERROR"
    assert body["error"]["status"] == 422
    assert body["error"]["details"][0]["field"] == "email"


@pytest.mark.asyncio
async def test_postgres_exception_handler_maps_unique_violation_to_conflict():
    response = await postgres_exception_handler(
        make_request(),
        asyncpg.UniqueViolationError("duplicate key"),
    )

    body = json_body(response)
    assert response.status_code == 409
    assert body["error"]["code"] == "CONFLICT"


@pytest.mark.asyncio
async def test_httpx_request_exception_handler_maps_timeout_to_upstream_error():
    request = httpx.Request("GET", "https://example.com")
    response = await httpx_request_exception_handler(
        make_request(),
        httpx.ReadTimeout("timeout", request=request),
    )

    body = json_body(response)
    assert response.status_code == 504
    assert body["error"]["code"] == "UPSTREAM_ERROR"
    assert body["error"]["status"] == 504
