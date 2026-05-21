import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.jwt_utils import create_jwt_token
from app.sso.oidc.endpoints import introspect


def json_body(response):
    return json.loads(response.body)


def make_request(body: dict, *, bloom_filter=None, auth_header: str = ""):
    request = MagicMock()
    request.headers.get.side_effect = lambda key, default="": {
        "content-type": "application/json",
        "Authorization": auth_header,
    }.get(key, default)
    request.json = AsyncMock(return_value=body)
    request.app = SimpleNamespace(state=SimpleNamespace(bloom_filter=bloom_filter or set()))
    return request


@pytest.mark.asyncio
async def test_introspect_active_access_token(mock_db_connection, mock_audit_logger):
    token = create_jwt_token({
        "sub": "user@example.com",
        "user_id": "user-1",
        "tenant_id": "tenant-1",
        "aud": "client-1",
        "scope": "openid profile",
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        "iat": datetime.now(timezone.utc),
    })
    request = make_request({"token": token, "client_id": "client-1", "client_secret": "secret"})

    with patch(
        "app.sso.oidc.endpoints.OIDCService.validate_client",
        new=AsyncMock(return_value={"client_id": "client-1", "id": "client-1"}),
    ):
        response = await introspect(request=request, db=mock_db_connection, logger=mock_audit_logger)

    body = json_body(response)
    assert body["active"] is True
    assert body["client_id"] == "client-1"
    assert body["sub"] == "user@example.com"


@pytest.mark.asyncio
async def test_introspect_revoked_access_token_returns_inactive(mock_db_connection, mock_audit_logger):
    token = create_jwt_token({
        "sub": "user@example.com",
        "user_id": "user-1",
        "tenant_id": "tenant-1",
        "aud": "client-1",
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        "iat": datetime.now(timezone.utc),
    })
    jti = __import__("jwt").decode(
        token,
        options={"verify_signature": False, "verify_exp": False, "verify_aud": False},
    )["jti"]
    request = make_request(
        {"token": token, "client_id": "client-1", "client_secret": "secret"},
        bloom_filter={jti},
    )

    with patch(
        "app.sso.oidc.endpoints.OIDCService.validate_client",
        new=AsyncMock(return_value={"client_id": "client-1", "id": "client-1"}),
    ):
        response = await introspect(request=request, db=mock_db_connection, logger=mock_audit_logger)

    assert json_body(response) == {"active": False}


@pytest.mark.asyncio
async def test_introspect_refresh_token(mock_db_connection, mock_audit_logger):
    request = make_request({
        "token": "refresh-token-1",
        "token_type_hint": "refresh_token",
        "client_id": "client-1",
        "client_secret": "secret",
    })
    refresh_row = {
        "jti": "refresh-token-1",
        "user_id": "user-1",
        "tenant_id": "tenant-1",
        "client_id": "client-1",
        "expires_at": datetime.now(timezone.utc) + timedelta(days=1),
        "created_at": datetime.now(timezone.utc),
    }

    with patch(
        "app.sso.oidc.endpoints.OIDCService.validate_client",
        new=AsyncMock(return_value={"client_id": "client-1", "id": "client-1"}),
    ), patch(
        "app.sso.oidc.endpoints.OIDCService.validate_refresh_token",
        new=AsyncMock(return_value=refresh_row),
    ):
        response = await introspect(request=request, db=mock_db_connection, logger=mock_audit_logger)

    body = json_body(response)
    assert body["active"] is True
    assert body["token_type"] == "refresh_token"
    assert body["jti"] == "refresh-token-1"
