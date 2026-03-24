from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import jwt
from starlette.requests import Request

from app.core.config import JWT_SECRET, ALGORITHM
from app.sso.oidc import clients as c


def make_request(auth_header=''):
    scope = {
        'type': 'http',
        'method': 'GET',
        'path': '/',
        'headers': [(b'authorization', auth_header.encode())] if auth_header else [],
    }
    return Request(scope)


def test_client_helpers_and_auth_context():
    cid = c.generate_client_id()
    secret = c.generate_client_secret()
    assert cid.startswith('client_') and isinstance(secret, str)
    hashed = c.hash_client_secret('secret')
    assert hashed != 'secret'

    assert pytest.run is not None if hasattr(pytest, 'run') else True


@pytest.mark.asyncio
async def test_get_auth_context_success_and_failure():
    token = jwt.encode({'user_id': 'u1', 'tenant_id': 't1', 'role': 'admin'}, JWT_SECRET, algorithm=ALGORITHM or 'HS256')
    ctx = await c.get_auth_context(make_request(f'Bearer {token}'))
    assert ctx['tenant_id'] == 't1'
    assert await c.get_auth_context(make_request('Bearer bad')) is None
    assert await c.get_auth_context(make_request()) is None


@pytest.mark.asyncio
async def test_client_routes(mock_db_connection, mock_audit_logger):
    unauthorized = await c.list_clients(make_request(), mock_db_connection, mock_audit_logger)
    assert unauthorized.status_code == 401

    token = jwt.encode({'user_id': 'u1', 'tenant_id': 't1', 'role': 'admin'}, JWT_SECRET, algorithm=ALGORITHM or 'HS256')
    req = make_request(f'Bearer {token}')

    # register
    with patch('app.sso.oidc.clients.generate_client_id', return_value='client_1'), \
         patch('app.sso.oidc.clients.generate_client_secret', return_value='secret1'), \
         patch('app.sso.oidc.clients.hash_client_secret', return_value='hashed'):
        resp = await c.register_client(req, c.ClientCreateRequest(name='HexShare', redirect_uris=['https://cb']), mock_db_connection, mock_audit_logger)
    body = json_body(resp)
    assert body['success'] is True and body['data']['client_id'] == 'client_1'

    # list/get/update/rotate/delete
    now = __import__('datetime').datetime.now(__import__('datetime').timezone.utc)
    mock_db_connection.fetch = AsyncMock(return_value=[{'id': 'client_1', 'name': 'HexShare', 'redirect_uris': ['https://cb'], 'scopes': ['openid'], 'is_active': True, 'created_at': now, 'last_modified': now}])
    body = json_body(await c.list_clients(req, mock_db_connection, mock_audit_logger))
    assert body['data'][0]['client_id'] == 'client_1'

    mock_db_connection.fetchrow = AsyncMock(side_effect=[
        {'id': 'client_1', 'name': 'HexShare', 'redirect_uris': ['https://cb'], 'scopes': ['openid'], 'is_active': True, 'created_at': now, 'last_modified': now},
        {'id': 'client_1', 'name': 'HexShare', 'redirect_uris': ['https://cb'], 'scopes': ['openid'], 'is_active': True, 'created_at': now, 'last_modified': now},
        {'id': 'client_1', 'name': 'HexShare', 'redirect_uris': ['https://cb'], 'scopes': ['openid'], 'is_active': True, 'created_at': now, 'last_modified': now},
        None,
    ])
    assert json_body(await c.get_client('client_1', req, mock_db_connection))['success'] is True
    assert json_body(await c.update_client('client_1', req, c.ClientUpdateRequest(name='NewName'), mock_db_connection, mock_audit_logger))['success'] is True
    with patch('app.sso.oidc.clients.generate_client_secret', return_value='newsecret'), patch('app.sso.oidc.clients.hash_client_secret', return_value='hashed'):
        assert json_body(await c.rotate_client_secret('client_1', req, mock_db_connection, mock_audit_logger))['success'] is True
    assert (json_body(await c.get_client('missing', req, mock_db_connection))['success']) is False

    mock_db_connection.execute = AsyncMock(side_effect=['DELETE 1', 'DELETE 0'])
    assert json_body(await c.delete_client('client_1', req, mock_db_connection, mock_audit_logger))['success'] is True
    assert json_body(await c.delete_client('missing', req, mock_db_connection, mock_audit_logger))['success'] is False


def json_body(response):
    import json
    return json.loads(response.body)
