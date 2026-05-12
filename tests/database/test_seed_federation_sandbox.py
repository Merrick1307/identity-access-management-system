import httpx
import pytest

from app.database import seed_federation_sandbox as sandbox


def test_seed_config_defaults_use_deliverable_domains():
    config = sandbox.SeedConfig()

    assert config.tenant_domain == "federation-sandbox.example.com"
    assert config.admin_email == "admin@federation-sandbox.example.com"
    assert config.sso_test_user_email == "federated.user@federation-sandbox.example.com"


@pytest.mark.asyncio
async def test_fetch_discovery_prefers_api_v1_path():
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(
            200,
            json={"issuer": "http://sso.local", "authorization_endpoint": "http://sso.local/api/v1/oidc/authorize"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        discovery, discovery_url = await sandbox._fetch_discovery(client, "http://sso.local")

    assert discovery["issuer"] == "http://sso.local"
    assert discovery_url == "http://sso.local/api/v1/.well-known/openid-configuration"
    assert calls == ["http://sso.local/api/v1/.well-known/openid-configuration"]


@pytest.mark.asyncio
async def test_fetch_discovery_falls_back_to_root_path():
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.path == "/api/v1/.well-known/openid-configuration":
            return httpx.Response(404)
        return httpx.Response(200, json={"issuer": "http://sso.local"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        discovery, discovery_url = await sandbox._fetch_discovery(client, "http://sso.local")

    assert discovery["issuer"] == "http://sso.local"
    assert discovery_url == "http://sso.local/.well-known/openid-configuration"
    assert calls == [
        "http://sso.local/api/v1/.well-known/openid-configuration",
        "http://sso.local/.well-known/openid-configuration",
    ]


@pytest.mark.asyncio
async def test_ensure_seed_data_persists_resolved_discovery_url(mock_db_connection, monkeypatch):
    mock_db_connection.fetchval.side_effect = [None, None]
    monkeypatch.setattr(sandbox, "hash_password", lambda _: "hashed-password")

    await sandbox._ensure_seed_data(
        mock_db_connection,
        config=sandbox.SeedConfig(),
        discovery={
            "issuer": "http://sso.local",
            "authorization_endpoint": "http://sso.local/api/v1/oidc/authorize",
            "token_endpoint": "http://sso.local/api/v1/oidc/token",
            "userinfo_endpoint": "http://sso.local/api/v1/oidc/userinfo",
            "jwks_uri": "http://sso.local/api/v1/oidc/jwks",
        },
        discovery_url="http://sso.local/api/v1/.well-known/openid-configuration",
        provider_id="provider-1",
        upstream_client={"client_id": "broker-client", "client_secret": "broker-secret"},
    )

    provider_call = next(
        call for call in mock_db_connection.execute.await_args_list
        if "INSERT INTO identity_providers" in call.args[0]
    )
    assert provider_call.args[7] == "http://sso.local/api/v1/.well-known/openid-configuration"
