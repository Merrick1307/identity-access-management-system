from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from app.api.v1 import tenants as routes
from app.core.jwt_utils import VerifiedTokenData
from app.models.tenants import TenantSettingsUpdate, MFASettings, TokenSettings, PasswordPolicy, BrandingSettings


def user(role='admin', tenant='tenant-1'):
    return VerifiedTokenData(email='user@example.com', tenant_id=tenant, policy={}, role=role, user_id='u1', exp=None, iat=None, aud='client')


@pytest.mark.asyncio
async def test_tenant_routes_success_and_permissions(mock_db_connection, mock_audit_logger):
    from unittest.mock import Mock

    req = Mock()
    req.app.state.redis = Mock()

    with patch('app.api.v1.tenants.tenant_service.get_tenant', new=AsyncMock(return_value={'id': 'tenant-1'})):
        resp = await routes.get_current_tenant(req, mock_db_connection)
    assert json_body(resp)['success'] is True

    with patch('app.api.v1.tenants.tenant_service.get_tenant_settings',
               new=AsyncMock(return_value={'mfa': {'enabled': False}})):
        resp = await routes.get_current_tenant_settings(req, mock_db_connection, user())
    assert json_body(resp)['success'] is True

    with pytest.raises(HTTPException):
        await routes.update_current_tenant_settings(req, TenantSettingsUpdate(), mock_db_connection, user(role='user'),
                                                    mock_audit_logger)

    with patch('app.api.v1.tenants.tenant_service.update_tenant_settings',
               new=AsyncMock(return_value={'mfa': {'enabled': True}})):
        resp = await routes.update_current_tenant_settings(req, TenantSettingsUpdate(mfa=MFASettings(enabled=True)),
                                                           mock_db_connection, user(), mock_audit_logger)
    assert json_body(resp)['success'] is True

    with patch('app.api.v1.tenants.tenant_service.update_mfa_settings',
               new=AsyncMock(return_value={'mfa': {'enabled': True}})):
        assert json_body(await routes.update_mfa_settings(req, MFASettings(enabled=True), mock_db_connection, user(),
                                                          mock_audit_logger))['success'] is True
    with patch('app.api.v1.tenants.tenant_service.update_token_settings',
               new=AsyncMock(return_value={'tokens': {'access_token_ttl': 1}})):
        assert json_body(await routes.update_token_settings(req,
                                                            TokenSettings(access_token_ttl=300, refresh_token_ttl=3600,
                                                                          id_token_ttl=300), mock_db_connection, user(),
                                                            mock_audit_logger))['success'] is True
    with patch('app.api.v1.tenants.tenant_service.update_password_policy',
               new=AsyncMock(return_value={'password_policy': {'min_length': 10}})):
        assert json_body(
            await routes.update_password_policy(req, PasswordPolicy(min_length=10), mock_db_connection, user(),
                                                mock_audit_logger))['success'] is True
    with patch('app.api.v1.tenants.tenant_service.update_branding',
               new=AsyncMock(return_value={'branding': {'company_name': 'Acme'}})):
        assert json_body(
            await routes.update_branding(req, BrandingSettings(company_name='Acme'), mock_db_connection, user(),
                                         mock_audit_logger))['success'] is True

    with pytest.raises(HTTPException):
        await routes.list_tenants(req, 1, 20, None, user(role='user'), mock_db_connection)

    with patch('app.api.v1.tenants.tenant_service.list_tenants', new=AsyncMock(return_value=([{'id': 't1'}], 1))):
        resp = await routes.list_tenants(req, 1, 20, None, user(role='superadmin'), mock_db_connection)
    assert json_body(resp)['success'] is True

    with patch('app.api.v1.tenants.tenant_service.get_tenant', new=AsyncMock(return_value=None)):
        resp = await routes.get_tenant('missing', req, user(role='superadmin'), mock_db_connection)
        assert json_body(resp)['success'] is False

def json_body(response):
    import json
    return json.loads(response.body)
