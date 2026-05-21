from unittest.mock import AsyncMock, patch

import jwt
import pytest
from fastapi import HTTPException, BackgroundTasks
from starlette.requests import Request

from app.api.v1.onboarding import verify_email, tenant_onboarding
from app.core.config import JWT_SECRET, ALGORITHM
from app.models.onboarding import TenantCreate, RootUserCreate, TenantOnboardingRequest


@pytest.mark.asyncio
async def test_verify_email_success_and_invalid(mock_db_connection, mock_audit_logger):
    token = jwt.encode({'user_id': 'user-1'}, JWT_SECRET, algorithm=ALGORITHM or 'HS256')
    mock_db_connection.fetchval = AsyncMock(return_value='tenant-1')
    mock_db_connection.execute = AsyncMock()
    resp = await verify_email(token, mock_db_connection, mock_audit_logger)
    assert json_body(resp)['message'] == 'Email verified successfully'

    with pytest.raises(HTTPException):
        await verify_email('bad-token', mock_db_connection, mock_audit_logger)


@pytest.mark.asyncio
async def test_verify_email_renders_html_for_browser(mock_db_connection, mock_audit_logger):
    token = jwt.encode({'user_id': 'user-1'}, JWT_SECRET, algorithm=ALGORITHM or 'HS256')
    mock_db_connection.fetchval = AsyncMock(return_value='tenant-1')
    mock_db_connection.execute = AsyncMock()
    request = Request({
        'type': 'http',
        'method': 'GET',
        'scheme': 'http',
        'server': ('testserver', 80),
        'client': ('testclient', 12345),
        'path': '/api/v1/onboarding/email/verify',
        'headers': [(b'accept', b'text/html')],
    })

    resp = await verify_email(token, mock_db_connection, mock_audit_logger, request=request)

    assert resp.status_code == 200
    assert 'text/html' in resp.headers['content-type']
    assert b'Email Verified' in resp.body


@pytest.mark.asyncio
async def test_tenant_onboarding_success(mock_db_connection, mock_audit_logger):
    req = TenantOnboardingRequest(
        tenant=TenantCreate(name='Acme', domain='acme.com'),
        user=RootUserCreate(email='admin@acme.com', password='Password123!', first_name='Admin', last_name='User', role='admin'),
        tenant_policies=[]
    )
    with patch('app.api.v1.onboarding.onboard_tenant', new=AsyncMock(return_value={'tenant_id': 'tenant-1', 'user_id': 'user-1'})):
        resp = await tenant_onboarding(request=req, connection=mock_db_connection, logger=mock_audit_logger, background_tasks=BackgroundTasks())
    assert json_body(resp)['data']['tenant_id'] == 'tenant-1'


def json_body(response):
    import json
    return json.loads(response.body)
