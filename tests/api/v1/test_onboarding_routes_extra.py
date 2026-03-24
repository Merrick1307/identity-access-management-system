from unittest.mock import AsyncMock, patch

import jwt
import pytest
from fastapi import HTTPException
from app.exceptions.http_error_module import HTTPError

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

    with pytest.raises((HTTPException, HTTPError)):
        await verify_email('bad-token', mock_db_connection, mock_audit_logger)


@pytest.mark.asyncio
async def test_tenant_onboarding_success(mock_db_connection, mock_audit_logger):
    req = TenantOnboardingRequest(
        tenant=TenantCreate(name='Acme', domain='acme.com'),
        user=RootUserCreate(email='admin@acme.com', password='Password123!', first_name='Admin', last_name='User', role='admin'),
        tenant_policies=[]
    )
    with patch('app.api.v1.onboarding.onboard_tenant', new=AsyncMock(return_value={'tenant_id': 'tenant-1', 'user_id': 'user-1'})):
        resp = await tenant_onboarding(req, mock_db_connection, mock_audit_logger)
    assert json_body(resp)['data']['tenant_id'] == 'tenant-1'


def json_body(response):
    import json
    return json.loads(response.body)
