from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from app.api.v1 import federation as routes
from app.core.jwt_utils import VerifiedTokenData
from app.models.federation import IdentityProviderCreate, IdentityProviderUpdate


def admin_user():
    return VerifiedTokenData(email='admin@example.com', tenant_id='tenant', policy={}, role='admin', user_id='u1', exp=None, iat=None, aud='client')


def non_admin_user():
    return VerifiedTokenData(email='user@example.com', tenant_id='tenant', policy={}, role='user', user_id='u2', exp=None, iat=None, aud='client')


def test_require_admin_raises():
    with pytest.raises(HTTPException):
        routes._require_admin(non_admin_user())


def test_serialize_provider_defaults():
    data = routes._serialize_provider({
        'id': 'p1', 'tenant_id': 't1', 'name': 'Okta', 'protocol': 'oidc', 'issuer_url': 'https://issuer',
        'created_at': datetime.now(timezone.utc), 'last_modified': None
    })
    assert data['authorization_scopes'] == 'openid profile email'
    assert data['claims_source'] == 'auto'


@pytest.mark.asyncio
async def test_route_success_and_not_found(mock_db_connection, mock_audit_logger, monkeypatch):
    from unittest.mock import Mock

    # Create mock request with redis
    mock_request = Mock()
    mock_request.app.state.redis = Mock()

    monkeypatch.setattr(routes.federation_service, 'list_identity_providers', AsyncMock(return_value=[
        {'id': 'p1', 'tenant_id': 'tenant', 'name': 'Okta', 'protocol': 'oidc', 'issuer_url': 'https://issuer'}]))
    resp = await routes.list_identity_providers(mock_request, mock_db_connection, admin_user())
    body = json_body(resp)
    assert body['success'] is True and len(body['data']) == 1

    payload = IdentityProviderCreate(name='Okta', protocol='oidc', issuer_url='https://issuer', client_id='cid')
    monkeypatch.setattr(routes.federation_service, 'create_identity_provider', AsyncMock(
        return_value={'id': 'p1', 'tenant_id': 'tenant', 'name': 'Okta', 'protocol': 'oidc',
                      'issuer_url': 'https://issuer'}))
    resp = await routes.create_identity_provider(mock_request, payload, mock_db_connection, admin_user(),
                                                 mock_audit_logger)
    assert json_body(resp)['success'] is True

    monkeypatch.setattr(routes.federation_service, 'get_identity_provider', AsyncMock(return_value=None))
    with pytest.raises(HTTPException):
        await routes.get_identity_provider('missing', mock_db_connection, admin_user())

    monkeypatch.setattr(routes.federation_service, 'update_identity_provider', AsyncMock(return_value=None))


def json_body(response):
    import json
    return json.loads(response.body)
