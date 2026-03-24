from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi_mail import FastMail

from app.models.onboarding import TenantCreate, RootUserCreate, Policy, TenantOnboardingRequest
from app.services import onboarding as svc


def test_load_template_and_build_html(tmp_path, monkeypatch):
    tpldir = tmp_path / 'templates' / 'onboarding'
    tpldir.mkdir(parents=True)
    (tpldir / 'verification.html').write_text('Hello {first_name} {verify_url} {app_name} {year}', encoding='utf-8')
    monkeypatch.setattr(svc, 'TEMPLATES_DIR', tmp_path / 'templates')
    html = svc._build_verification_email_html('Jane', 'https://verify')
    assert 'Hello Jane' in html and 'https://verify' in html


@pytest.mark.asyncio
async def test_create_helpers(mock_db_connection):
    tenant_id = await svc.create_tenant(mock_db_connection, TenantCreate(name='Acme', domain='acme.com'), 'admin@acme.com')
    assert tenant_id
    user_id = await svc.create_user(mock_db_connection, 'tenant', RootUserCreate(email='admin@acme.com', password='Password123!', first_name='A', last_name='B', role='admin'))
    assert user_id
    await svc.assign_policies(mock_db_connection, 'tenant', 'user', [])
    await svc.create_tenant_policies(mock_db_connection, 'tenant', [])
    assert mock_db_connection.executemany.await_count == 0


@pytest.mark.asyncio
async def test_send_verification_email(monkeypatch):
    mock_send = AsyncMock()
    monkeypatch.setattr(svc, '_build_verification_email_html', lambda first_name, verify_url: f'hi {first_name} {verify_url}')
    monkeypatch.setattr(svc, 'create_jwt_token', AsyncMock(return_value='token'))
    monkeypatch.setattr(FastMail, 'send_message', mock_send)
    await svc.send_verification_email('Jane', 'Doe', 'jane@example.com', 'user1', 'tenant1', None)
    assert mock_send.await_count == 1


@pytest.mark.asyncio
async def test_onboard_tenant_success_and_email_warning(mock_db_connection, mock_audit_logger, monkeypatch):
    request = TenantOnboardingRequest(
        tenant=TenantCreate(name='Acme', domain='acme.com'),
        user=RootUserCreate(email='admin@acme.com', password='Password123!', first_name='Admin', last_name='User', role='admin'),
        tenant_policies=[]
    )
    tx = MagicMock()
    tx.__aenter__ = AsyncMock(return_value=None)
    tx.__aexit__ = AsyncMock(return_value=None)
    mock_db_connection.transaction.return_value = tx
    monkeypatch.setattr(svc, 'create_tenant', AsyncMock(return_value='tenant-1'))
    monkeypatch.setattr(svc, 'create_user', AsyncMock(return_value='user-1'))
    monkeypatch.setattr(svc, 'assign_policies', AsyncMock(return_value=None))
    monkeypatch.setattr(svc, 'send_verification_email', AsyncMock(side_effect=Exception('mail down')))
    result = await svc.onboard_tenant(mock_db_connection, request, mock_audit_logger)
    assert result['tenant_id'] == 'tenant-1'
    assert result['verification_email_sent'] is False

    monkeypatch.setattr(svc, 'create_tenant', AsyncMock(side_effect=Exception('db fail')))
    with pytest.raises(Exception):
        await svc.onboard_tenant(mock_db_connection, request, mock_audit_logger)
