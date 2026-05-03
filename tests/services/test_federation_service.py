import json
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import jwt

from app.services import federation_service as fs


@pytest.mark.asyncio
async def test_provider_crud_and_links(mock_db_connection):
    mock_db_connection.fetch.return_value = [{"id": "p1"}]
    assert await fs.list_identity_providers(mock_db_connection, "t1") == [{"id": "p1", "created_at": None, "last_modified": None}]

    mock_db_connection.fetchrow.return_value = {"id": "p1", "tenant_id": "t1"}
    assert (await fs.get_identity_provider(mock_db_connection, "t1", "p1"))["id"] == "p1"

    payload = {"name": "Okta", "protocol": "oidc", "issuer_url": "https://issuer", "client_id": "cid"}
    with patch('app.services.federation_service.uuid4', return_value='prov-1'):
        created = await fs.create_identity_provider(mock_db_connection, "t1", payload)
    assert created["id"] == "p1"
    assert mock_db_connection.execute.await_count >= 1

    mock_db_connection.fetchrow.side_effect = [
        {"id": "p1", "tenant_id": "t1", "name": "old", "protocol": "oidc", "issuer_url": "https://issuer", "client_id": "cid"},
        {"id": "p1", "tenant_id": "t1", "name": "new"},
    ]
    updated = await fs.update_identity_provider(mock_db_connection, "t1", "p1", {"name": "new"})
    assert updated["name"] == "new"

    mock_db_connection.fetchrow.side_effect = None
    mock_db_connection.fetchrow.return_value = None
    assert await fs.update_identity_provider(mock_db_connection, "t1", "missing", {"name": "x"}) is None

    mock_db_connection.execute.return_value = 'DELETE 1'
    assert await fs.delete_identity_provider(mock_db_connection, "t1", "p1") is True
    mock_db_connection.execute.return_value = 'DELETE 0'
    assert await fs.delete_identity_provider(mock_db_connection, "t1", "p1") is False

    mock_db_connection.fetch.return_value = [{"id": "link-1"}]
    assert await fs.list_federated_links_for_provider(mock_db_connection, "t1", "p1") == [{"id": "link-1"}]


def test_normalized_email_verified_variants():
    assert fs._normalized_email_verified({"email_verified": True}) is True
    assert fs._normalized_email_verified({"email_verified": "true"}) is True
    assert fs._normalized_email_verified({"email_verified": "false"}) is False
    assert fs._normalized_email_verified({}) is False


@pytest.mark.asyncio
async def test_resolve_discovery_prefers_cached_and_url():
    provider = {"discovery_url": "https://issuer/.well-known/openid-configuration", "issuer_url": "https://issuer"}
    fs._DISCOVERY_CACHE.clear()
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = {"jwks_uri": "https://issuer/jwks"}
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    client.get.return_value = response
    with patch('app.services.federation_service.httpx.AsyncClient', return_value=client):
        result = await fs._resolve_discovery(provider)
    assert result["jwks_uri"] == "https://issuer/jwks"
    # cache hit
    with patch('app.services.federation_service.httpx.AsyncClient') as mocked:
        result2 = await fs._resolve_discovery(provider)
    assert result2 == result
    mocked.assert_not_called()


@pytest.mark.asyncio
async def test_verify_jwt_secret_and_jwks_paths():
    claims = {"sub": "ext-1"}
    provider_secret = {"jwt_validation_secret": "secret", "issuer_url": "https://issuer"}
    with patch('app.services.federation_service.jwt.decode', return_value=claims) as decode:
        result = await fs._verify_jwt('token', provider_secret, 'aud1')
    assert result == claims
    decode.assert_called_once()

    provider_jwks = {"jwks_uri": "https://issuer/jwks", "issuer_url": "https://issuer"}
    fake_signing_key = MagicMock(key='public-key')
    fake_client = MagicMock()
    fake_client.get_signing_key_from_jwt.return_value = fake_signing_key
    with patch('app.services.federation_service.jwt.PyJWKClient', return_value=fake_client), \
         patch('app.services.federation_service.jwt.decode', return_value=claims) as decode:
        result = await fs._verify_jwt('token', provider_jwks, 'aud1')
    assert result == claims
    decode.assert_called_once()


@pytest.mark.asyncio
async def test_validate_broker_subject_token_and_resolve_or_provision(mock_db_connection):
    token = jwt.encode({"iss": "https://issuer", "sub": "user-1"}, 'x'*32, algorithm='HS256')
    provider = {"id": "prov-1", "issuer_url": "https://issuer", "protocol": "oidc", "enabled": True}
    mock_db_connection.fetchrow.return_value = provider
    with patch('app.services.federation_service._verify_jwt', new=AsyncMock(return_value={"iss": "https://issuer", "sub": "user-1", "email": 'a@b.com'})):
        result = await fs.validate_broker_subject_token(mock_db_connection, 'tenant-1', token, 'aud1')
    assert result.provider["id"] == 'prov-1'

    with patch('app.services.federation_service.validate_broker_subject_token', new=AsyncMock(return_value=None)):
        with pytest.raises(ValueError):
            await fs.resolve_or_provision_federated_user(mock_db_connection, 'tenant-1', token, 'aud1')

    with patch('app.services.federation_service.validate_broker_subject_token', new=AsyncMock(return_value=fs.BrokerValidationResult(provider=provider, claims={"sub": "user-1", "email": "a@b.com", "email_verified": True}))), \
         patch('app.services.federation_service._find_or_create_local_user', new=AsyncMock(return_value={"id": "local-user"})):
        user, prov, claims = await fs.resolve_or_provision_federated_user(mock_db_connection, 'tenant-1', token, 'aud1')
    assert user["id"] == 'local-user'
    assert prov["id"] == 'prov-1'
    assert claims["sub"] == 'user-1'


@pytest.mark.asyncio
async def test_find_or_create_local_user_branches(mock_db_connection):
    provider = {"id": "prov", "auto_link": True, "link_by_email_verified_only": True, "default_role": "member"}
    claims = {"sub": "ext-sub", "email": "user@example.com", "email_verified": True, "given_name": "Jane", "family_name": "Doe"}

    # existing link
    mock_db_connection.fetchrow.return_value = {"id": "local-1", "email": "user@example.com"}
    user = await fs._find_or_create_local_user(mock_db_connection, 'tenant', provider, claims)
    assert user["id"] == 'local-1'

    # auto-link disabled
    mock_db_connection.fetchrow.side_effect = [None]
    provider_disabled = {**provider, "auto_link": False}
    with pytest.raises(ValueError):
        await fs._find_or_create_local_user(mock_db_connection, 'tenant', provider_disabled, claims)

    # existing user but email unverified
    mock_db_connection.fetchrow.side_effect = [None, {"id": "local-2", "email": "user@example.com"}]
    with pytest.raises(ValueError):
        await fs._find_or_create_local_user(mock_db_connection, 'tenant', provider, {**claims, "email_verified": False})

    # create new user and link
    mock_db_connection.fetchrow.side_effect = [None, None, {"id": "created-user", "email": "user@example.com"}]
    mock_db_connection.execute = AsyncMock()
    with patch('app.services.federation_service.uuid4', side_effect=['new-user', 'new-link']), \
         patch('app.services.federation_service.hash_password', return_value='hashed'):
        user = await fs._find_or_create_local_user(mock_db_connection, 'tenant', provider, claims)
    assert user["id"] == 'created-user'
    assert mock_db_connection.execute.await_count >= 2


@pytest.mark.asyncio
async def test_enabled_providers_transactions_and_provider_helpers(mock_db_connection):
    mock_db_connection.fetch.return_value = [{"id": "p1"}, {"id": "p2"}]
    providers = await fs.list_enabled_identity_providers(mock_db_connection, 'tenant')
    assert len(providers) == 2

    mock_db_connection.fetchrow.return_value = {"id": "tx1", "upstream_state": "state1"}
    with patch('app.services.federation_service.uuid4', return_value='tx1'):
        tx = await fs.create_federation_auth_transaction(
            mock_db_connection, tenant_id='tenant', provider_id='p1', client_id='c1', redirect_uri='https://cb',
            scope='openid', state='s', nonce='n', code_challenge='cc', code_challenge_method='S256', upstream_state='state1', upstream_nonce='nonce'
        )
    assert tx['id'] == 'tx1'
    got = await fs.get_federation_auth_transaction_by_state(mock_db_connection, provider_id='p1', upstream_state='state1')
    assert got['id'] == 'tx1'
    await fs.consume_federation_auth_transaction(mock_db_connection, 'tx1')
    assert mock_db_connection.execute.await_count >= 1

    provider = {"id": "p1", "name": "Okta", "issuer_url": "https://issuer", "client_id": "cid", "authorization_scopes": 'openid email', 'authorization_endpoint': 'https://issuer/auth'}
    url = await fs.build_provider_authorize_url(provider, redirect_uri='https://cb', upstream_state='state', upstream_nonce='nonce')
    assert 'client_id=cid' in url and 'state=state' in url and 'nonce=nonce' in url

    provider_missing = {"client_id": "cid", "discovery_url": 'https://issuer/.well-known/openid-configuration'}
    with patch('app.services.federation_service._resolve_discovery', new=AsyncMock(return_value={'authorization_endpoint': 'https://issuer/auth'})):
        url = await fs.build_provider_authorize_url(provider_missing, redirect_uri='https://cb', upstream_state='state', upstream_nonce=None)
    assert url.startswith('https://issuer/auth?')


@pytest.mark.asyncio
async def test_exchange_code_fetch_userinfo_and_resolve_from_tokens():
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = {"access_token": "access", "id_token": "idtok"}
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    client.post.return_value = response
    provider = {"client_id": 'cid', "client_secret": 'secret', "token_endpoint": 'https://issuer/token', 'token_endpoint_auth_method': 'client_secret_basic'}
    with patch('app.services.federation_service.httpx.AsyncClient', return_value=client):
        tokens = await fs.exchange_code_for_provider_tokens(provider, code='abc', redirect_uri='https://cb')
    assert tokens['access_token'] == 'access'
    headers = client.post.call_args.kwargs['headers']
    assert 'Authorization' in headers

    response2 = MagicMock()
    response2.raise_for_status.return_value = None
    response2.json.return_value = {"sub": "user-1", "email": "a@b.com"}
    client2 = AsyncMock()
    client2.__aenter__.return_value = client2
    client2.__aexit__.return_value = None
    client2.get.return_value = response2
    with patch('app.services.federation_service.httpx.AsyncClient', return_value=client2):
        info = await fs.fetch_userinfo({"userinfo_endpoint": 'https://issuer/userinfo'}, access_token='access')
    assert info['sub'] == 'user-1'

    provider = {'client_id': 'cid', 'claims_source': 'auto', 'issuer_url': 'https://issuer'}
    with patch('app.services.federation_service._verify_jwt', new=AsyncMock(return_value={'sub': 'user-1', 'email': 'a@b.com'})), \
         patch('app.services.federation_service._find_or_create_local_user', new=AsyncMock(return_value={'id': 'local'})):
        user, claims = await fs.resolve_or_provision_from_provider_tokens(AsyncMock(), tenant_id='tenant', provider=provider, tokens={'id_token': 'idtok', 'access_token': 'access'})
    assert user['id'] == 'local'
    assert claims['sub'] == 'user-1'

    provider_userinfo = {'client_id': 'cid', 'claims_source': 'userinfo', 'issuer_url': 'https://issuer'}
    with patch('app.services.federation_service.fetch_userinfo', new=AsyncMock(return_value={'sub': 'user-2'})), \
         patch('app.services.federation_service._find_or_create_local_user', new=AsyncMock(return_value={'id': 'local-2'})):
        user, claims = await fs.resolve_or_provision_from_provider_tokens(AsyncMock(), tenant_id='tenant', provider=provider_userinfo, tokens={'access_token': 'access'})
    assert user['id'] == 'local-2'
    assert claims['iss'] == 'https://issuer'

    with pytest.raises(ValueError):
        await fs.resolve_or_provision_from_provider_tokens(AsyncMock(), tenant_id='tenant', provider={'claims_source': 'auto', 'issuer_url': 'https://issuer'}, tokens={})
