from datetime import datetime, timezone
import json

import pytest

from app.api.v1.users import list_tenant_users, get_user_by_id
from app.core.jwt_utils import VerifiedTokenData


def user():
    return VerifiedTokenData(email='admin@example.com', tenant_id='tenant-1', policy={}, role='admin', user_id='u1', exp=None, iat=None, aud='client')


def json_body(response):
    return json.loads(response.body)


@pytest.mark.asyncio
async def test_list_users_and_get_user(mock_db_connection, mock_audit_logger):
    now = datetime.now(timezone.utc)
    mock_db_connection.fetchval = pytest.AsyncMock(side_effect=[2, 1]) if hasattr(pytest, 'AsyncMock') else None
    from unittest.mock import AsyncMock
    mock_db_connection.fetchval = AsyncMock(side_effect=[2, 1])
    mock_db_connection.fetch = AsyncMock(side_effect=[[
        {'id': 'u1', 'email': 'a@example.com', 'first_name': 'A', 'last_name': 'One', 'role': 'admin', 'is_active': True, 'created_at': now},
        {'id': 'u2', 'email': 'b@example.com', 'first_name': 'B', 'last_name': 'Two', 'role': 'member', 'is_active': True, 'created_at': now},
    ], [
        {'id': 'u1', 'email': 'a@example.com', 'first_name': 'A', 'last_name': 'One', 'role': 'admin', 'is_active': True, 'created_at': now},
    ]])
    body = json_body(await list_tenant_users(1, 50, None, mock_db_connection, user(), mock_audit_logger))
    assert body['data']['pagination']['total_items'] == 2
    body = json_body(await list_tenant_users(1, 50, 'a@example.com', mock_db_connection, user(), mock_audit_logger))
    assert body['data']['users'][0]['email'] == 'a@example.com'

    mock_db_connection.fetchrow = AsyncMock(return_value=None)
    body = json_body(await get_user_by_id('missing', mock_db_connection, user()))
    assert body['data'] is None

    mock_db_connection.fetchrow = AsyncMock(return_value={'id': 'u1', 'email': 'a@example.com', 'first_name': 'A', 'last_name': 'One', 'role': 'admin', 'is_active': True, 'email_verified': True, 'created_at': now, 'last_login': now})
    body = json_body(await get_user_by_id('u1', mock_db_connection, user()))
    assert body['data']['id'] == 'u1'
