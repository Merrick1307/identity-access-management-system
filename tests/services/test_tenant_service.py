from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from app.services import tenant_service


@pytest.mark.asyncio
async def test_get_tenant_and_settings_and_merge(mock_db_connection, mock_audit_logger):
    mock_db_connection.fetchrow = AsyncMock(return_value={
        'id': 'tenant-1', 'name': 'Acme', 'domain': 'acme.com', 'root': 'admin@acme.com',
        'settings': '{"mfa": {"enabled": true}}', 'is_active': True, 'created_at': datetime.now(timezone.utc)
    })
    tenant = await tenant_service.get_tenant(mock_db_connection, 'tenant-1')
    assert tenant.name == 'Acme'

    settings = await tenant_service.get_tenant_settings(mock_db_connection, 'tenant-1')
    assert settings.mfa['enabled'] is True
    merged = tenant_service._merge_settings({'a': {'b': 1}, 'x': 2}, {'a': {'c': 3}, 'x': 4})
    assert merged['a']['b'] == 1 and merged['a']['c'] == 3 and merged['x'] == 4

    mock_db_connection.fetchrow = AsyncMock(return_value=None)
    settings = await tenant_service.get_tenant_settings(mock_db_connection, 'tenant-1')
    assert settings.tokens['access_token_ttl'] == 3600


@pytest.mark.asyncio
async def test_update_settings_variants_and_list_activate(mock_db_connection, mock_audit_logger):
    current = tenant_service.TenantSettingsResponse(**tenant_service.DEFAULT_SETTINGS)
    with patch('app.services.tenant_service.get_tenant_settings', new=AsyncMock(return_value=current)):
        updated = await tenant_service.update_tenant_settings(mock_db_connection, 'tenant-1', {'branding': {'company_name': 'Acme'}}, mock_audit_logger)
    assert updated['branding']['company_name'] == 'Acme'
    assert mock_db_connection.execute.await_count == 1

    with patch('app.services.tenant_service.get_tenant_settings', new=AsyncMock(return_value=current)), \
         patch('app.services.tenant_service.update_tenant_settings', new=AsyncMock(side_effect=lambda db, tenant_id, settings, logger: settings)):
        mfa = await tenant_service.update_mfa_settings(mock_db_connection, 'tenant-1', True, True, ['totp'], mock_audit_logger)
        tokens = await tenant_service.update_token_settings(mock_db_connection, 'tenant-1', 10, 20, 30, mock_audit_logger)
        password = await tenant_service.update_password_policy(mock_db_connection, 'tenant-1', {'min_length': 12}, mock_audit_logger)
        branding = await tenant_service.update_branding(mock_db_connection, 'tenant-1', {'company_name': 'Acme'}, mock_audit_logger)
    assert mfa['mfa']['enabled'] is True
    assert tokens['tokens']['access_token_ttl'] == 10
    assert password['password_policy']['min_length'] == 12
    assert branding['branding']['company_name'] == 'Acme'

    now = datetime.now(timezone.utc)
    mock_db_connection.fetchval = AsyncMock(side_effect=[2, 1])
    mock_db_connection.fetch = AsyncMock(side_effect=[[
        {'id': 't1', 'name': 'Acme', 'domain': 'acme.com', 'root': 'admin@acme.com', 'settings': '{}', 'is_active': True, 'created_at': now},
        {'id': 't2', 'name': 'Beta', 'domain': 'beta.com', 'root': 'admin@beta.com', 'settings': {}, 'is_active': False, 'created_at': now}
    ], [
        {'id': 't1', 'name': 'Acme', 'domain': 'acme.com', 'root': 'admin@acme.com', 'settings': {}, 'is_active': True, 'created_at': now}
    ]])
    tenants, total = await tenant_service.list_tenants(mock_db_connection)
    assert total == 2 and len(tenants) == 2
    tenants, total = await tenant_service.list_tenants(mock_db_connection, search='Acme')
    assert total == 1 and tenants[0].name == 'Acme'

    assert await tenant_service.deactivate_tenant(mock_db_connection, 'tenant-1', mock_audit_logger) is True
    assert await tenant_service.activate_tenant(mock_db_connection, 'tenant-1', mock_audit_logger) is True
