from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import BackgroundTasks

from app.models.onboarding import TenantCreate, RootUserCreate, TenantOnboardingRequest
from app.services import onboarding as svc


@pytest.mark.asyncio
async def test_create_helpers(mock_db_connection):
    tenant_id = await svc.create_tenant(
        mock_db_connection,
        TenantCreate(name='Acme', domain='acme.com'),
        'admin@acme.com',
    )
    assert tenant_id
    user_id = await svc.create_user(
        mock_db_connection,
        'tenant',
        RootUserCreate(
            email='admin@acme.com',
            password='Password123!',
            first_name='A',
            last_name='B',
            role='admin',
        ),
    )
    assert user_id
    await svc.assign_policies(mock_db_connection, 'tenant', 'user', [])
    await svc.create_tenant_policies(mock_db_connection, 'tenant', [])
    assert mock_db_connection.executemany.await_count == 0


def make_request_payload():
    return TenantOnboardingRequest(
        tenant=TenantCreate(name='Acme', domain='acme.com'),
        user=RootUserCreate(
            email='admin@acme.com',
            password='Password123!',
            first_name='Admin',
            last_name='User',
            role='admin'
        ),
        tenant_policies=[]
    )


@pytest.mark.asyncio
async def test_onboard_tenant_success(mock_db_connection, mock_audit_logger, monkeypatch):
    tx = MagicMock()
    tx.__aenter__ = AsyncMock(return_value=None)
    tx.__aexit__ = AsyncMock(return_value=None)
    mock_db_connection.transaction.return_value = tx

    monkeypatch.setattr(svc, 'create_tenant', AsyncMock(return_value='tenant-1'))
    monkeypatch.setattr(svc, 'create_user', AsyncMock(return_value='user-1'))
    monkeypatch.setattr(svc, 'assign_policies', AsyncMock(return_value=None))

    email_service = SimpleNamespace(send_verification_email=AsyncMock())
    monkeypatch.setattr(svc, 'get_email_service', lambda: email_service)

    background_tasks = BackgroundTasks()
    result = await svc.onboard_tenant(
        mock_db_connection,
        make_request_payload(),
        background_tasks,
        mock_audit_logger,
    )

    assert result['tenant_id'] == 'tenant-1'
    assert result['verification_email_sent'] is True
    assert len(background_tasks.tasks) == 1
    assert background_tasks.tasks[0].func is email_service.send_verification_email


@pytest.mark.asyncio
async def test_onboard_tenant_preserves_original_exception(mock_db_connection, mock_audit_logger, monkeypatch):
    tx = MagicMock()
    tx.__aenter__ = AsyncMock(return_value=None)
    tx.__aexit__ = AsyncMock(return_value=None)
    mock_db_connection.transaction.return_value = tx

    monkeypatch.setattr(svc, 'create_tenant', AsyncMock(side_effect=RuntimeError('db fail')))

    with pytest.raises(RuntimeError, match='db fail'):
        await svc.onboard_tenant(
            mock_db_connection,
            make_request_payload(),
            BackgroundTasks(),
            mock_audit_logger,
        )
