import json
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from fastapi import FastAPI, HTTPException
from starlette.requests import Request

from app.core.config import JWT_SECRET
from app.main import health_check, _unauthorized_response, _bad_request_response, middle_ware
from app import main as main_module
from app.database import run_migrations, get_database_pool, get_database_pool_no_tenant


def make_request(path='/', headers=None, query_string=b'', app=None, state=None):
    scope = {
        'type': 'http',
        'method': 'GET',
        'path': path,
        'headers': [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        'query_string': query_string,
        'app': app or SimpleNamespace(state=state or SimpleNamespace(bloom_filter=set(), db_pool=None, db_owner_pool=None)),
    }
    req = Request(scope)
    return req


def test_health_and_response_helpers():
    assert health_check() == {'status': 'ok'}
    assert _unauthorized_response('bad').status_code == 401
    assert _bad_request_response('bad').status_code == 400


@pytest.mark.asyncio
async def test_main_middleware_branches():
    async def call_next(_):
        return _bad_request_response('next')

    # public path bypass
    req = make_request('/health')
    resp = await middle_ware(req, call_next)
    assert resp.status_code == 400

    # missing auth header
    req = make_request('/api/v1/users')
    resp = await middle_ware(req, call_next)
    assert resp.status_code == 401

    # bad token format
    req = make_request('/api/v1/users', headers={'Authorization': 'Bearer nope'})
    resp = await middle_ware(req, call_next)
    assert resp.status_code == 401

    # missing jti
    token = jwt.encode({'sub': 'u'}, JWT_SECRET, algorithm='HS256')
    req = make_request('/api/v1/users', headers={'Authorization': f'Bearer {token}'})
    resp = await middle_ware(req, call_next)
    assert resp.status_code == 401

    # revoked token
    token = jwt.encode({'sub': 'u'}, JWT_SECRET, algorithm='HS256', headers={'jti': 'revoked'})
    app = SimpleNamespace(state=SimpleNamespace(bloom_filter={'revoked'}))
    req = make_request('/api/v1/users', headers={'Authorization': f'Bearer {token}'}, app=app)
    resp = await middle_ware(req, call_next)
    assert resp.status_code == 401

    # valid flow
    token = jwt.encode({'sub': 'u'}, JWT_SECRET, algorithm='HS256', headers={'jti': 'ok'})
    app = SimpleNamespace(state=SimpleNamespace(bloom_filter=set()))
    req = make_request('/api/v1/users', headers={'Authorization': f'Bearer {token}'}, app=app)
    resp = await middle_ware(req, call_next)
    assert resp.status_code == 400


def test_run_migrations_paths():
    migration1 = SimpleNamespace(id='001')
    migration2 = SimpleNamespace(id='002')
    backend = MagicMock()
    backend.to_apply.side_effect = [[migration1, migration2], [migration1, migration2]]
    backend.to_rollback.return_value = [migration1]
    with patch('app.database.get_backend', return_value=backend), patch('app.database.read_migrations', return_value=[migration1, migration2]):
        result = run_migrations('postgres://db', auto_apply=True)
    assert result['pending_count'] == 2
    assert result['newly_applied'] == ['001', '002']
    backend.connection.close.assert_called_once()

    backend = MagicMock()
    backend.to_apply.return_value = [migration1]
    backend.to_rollback.return_value = []
    with patch('app.database.get_backend', return_value=backend), patch('app.database.read_migrations', return_value=[migration1]):
        result = run_migrations('postgres://db', auto_apply=False)
    assert result['pending_count'] == 1 and result['newly_applied'] == []

    class UniqueViolation(Exception):
        pass
    backend = MagicMock()
    backend.to_apply.side_effect = [[migration1], [migration1]]
    backend.to_rollback.return_value = []
    backend.apply_migrations.side_effect = UniqueViolation('duplicate key')
    with patch('app.database.get_backend', return_value=backend), patch('app.database.read_migrations', return_value=[migration1]):
        result = run_migrations('postgres://db', auto_apply=True)
    assert result['pending'] == ['001']


@pytest.mark.asyncio
async def test_get_database_pool_and_no_tenant():
    conn = AsyncMock()
    acquire_cm = AsyncMock()
    acquire_cm.__aenter__.return_value = conn
    acquire_cm.__aexit__.return_value = None
    db_pool = MagicMock()
    db_pool.acquire.return_value = acquire_cm
    req = make_request('/x', headers={'X-TENANT-ID': 'tenant-1'}, app=SimpleNamespace(state=SimpleNamespace(db_pool=db_pool)))
    gen = get_database_pool(req)
    yielded = await anext(gen)
    assert yielded is conn
    conn.execute.assert_awaited_with("SELECT set_config('app.tenant_id', $1, false)", 'tenant-1')
    with pytest.raises(StopAsyncIteration):
        await gen.__anext__()

    # resolve tenant from client_id in query params
    temp_conn = AsyncMock()
    acquire_cm2 = AsyncMock()
    acquire_cm2.__aenter__.return_value = temp_conn
    acquire_cm2.__aexit__.return_value = None
    db_pool.acquire.return_value = acquire_cm2
    temp_conn.fetchval = AsyncMock(return_value='tenant-from-client')
    req = make_request('/x', query_string=b'client_id=abc', app=SimpleNamespace(state=SimpleNamespace(db_pool=db_pool)))
    gen = get_database_pool(req)
    yielded = await anext(gen)
    assert yielded is temp_conn

    # missing tenant entirely
    req = make_request('/x', app=SimpleNamespace(state=SimpleNamespace(db_pool=db_pool)))
    with pytest.raises(HTTPException):
        await anext(get_database_pool(req))

    # no tenant pool
    owner_conn = AsyncMock()
    owner_cm = AsyncMock()
    owner_cm.__aenter__.return_value = owner_conn
    owner_cm.__aexit__.return_value = None
    app = SimpleNamespace(state=SimpleNamespace(db_owner_pool=MagicMock(acquire=MagicMock(return_value=owner_cm))))
    req = make_request('/x', app=app)
    gen = get_database_pool_no_tenant(req)
    assert await anext(gen) is owner_conn

