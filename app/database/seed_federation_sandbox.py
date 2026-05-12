"""
Seed a local federation sandbox for HEX IAM and the companion hexalgon-sso app.

Run:
    python -m app.database.seed_federation_sandbox

Relevant environment variables:
    IAM_APP_BASE_URL
    HEXALGON_SSO_BASE_URL
    FEDERATION_TEST_TENANT_ID
    FEDERATION_TEST_TENANT_NAME
    FEDERATION_TEST_TENANT_DOMAIN
    FEDERATION_TEST_ADMIN_EMAIL
    FEDERATION_TEST_ADMIN_PASSWORD
    FEDERATION_TEST_OIDC_CLIENT_ID
    FEDERATION_TEST_OIDC_CLIENT_SECRET
    FEDERATION_TEST_OIDC_REDIRECT_URI
    HEXALGON_SSO_PROVIDER_ID
    HEXALGON_SSO_PROVIDER_NAME
    HEXALGON_SSO_CLIENT_ID
    HEXALGON_SSO_CLIENT_SECRET
    HEXALGON_SSO_TEST_USER_EMAIL
    HEXALGON_SSO_TEST_USER_PASSWORD
    SEED_UPSTREAM_USER
"""
import asyncio
import json
import os
from dataclasses import dataclass
from typing import Any

import asyncpg
import httpx

from app.core.config import APP_BASE_URL, db_owner_connection_string
from app.core.security import hash_password


ALL_ACTIONS = [
    "read",
    "write",
    "delete",
    "approve",
    "reject",
    "execute",
    "assign",
    "manage",
    "export",
    "import",
    "activate",
    "archive",
]
ADMIN_POLICY_RESOURCES = [
    "users",
    "policies",
    "sessions",
    "oidc",
    "federation",
    "organizations",
]


def _env_flag(name: str, default: bool) -> bool:
    return os.getenv(name, str(default).lower()).strip().lower() in {"1", "true", "yes", "on"}


def _normalized_base_url(url: str) -> str:
    return url.rstrip("/")


def _provider_callback_uri(iam_base_url: str, provider_id: str) -> str:
    return f"{_normalized_base_url(iam_base_url)}/api/v1/oidc/federation/callback/{provider_id}"


def _admin_policy(resource: str) -> str:
    return json.dumps({
        "resource": resource,
        "actions": ALL_ACTIONS,
        "conditions": {},
    })


@dataclass(slots=True)
class SeedConfig:
    iam_base_url: str = os.getenv("IAM_APP_BASE_URL", APP_BASE_URL)
    sso_base_url: str = os.getenv("HEXALGON_SSO_BASE_URL", "http://localhost:8100")
    tenant_id: str = os.getenv("FEDERATION_TEST_TENANT_ID", "tenant-federation-sandbox")
    tenant_name: str = os.getenv("FEDERATION_TEST_TENANT_NAME", "Federation Sandbox")
    tenant_domain: str = os.getenv("FEDERATION_TEST_TENANT_DOMAIN", "federation-sandbox.example.com")
    admin_user_id: str = os.getenv("FEDERATION_TEST_ADMIN_USER_ID", "user-federation-admin")
    admin_email: str = os.getenv("FEDERATION_TEST_ADMIN_EMAIL", "admin@federation-sandbox.example.com")
    admin_password: str = os.getenv("FEDERATION_TEST_ADMIN_PASSWORD", "HexalgonAdmin123!")
    admin_first_name: str = os.getenv("FEDERATION_TEST_ADMIN_FIRST_NAME", "Federation")
    admin_last_name: str = os.getenv("FEDERATION_TEST_ADMIN_LAST_NAME", "Admin")
    oidc_client_id: str = os.getenv("FEDERATION_TEST_OIDC_CLIENT_ID", "")
    oidc_client_secret: str = os.getenv("FEDERATION_TEST_OIDC_CLIENT_SECRET", "")
    oidc_client_name: str = os.getenv("FEDERATION_TEST_OIDC_CLIENT_NAME", "Federation Test Client")
    oidc_client_redirect_uri: str = os.getenv("FEDERATION_TEST_OIDC_REDIRECT_URI", "http://localhost:8099/api/auth/callback")
    provider_id: str = os.getenv("HEXALGON_SSO_PROVIDER_ID", "hexalgon-sso-local")
    provider_name: str = os.getenv("HEXALGON_SSO_PROVIDER_NAME", "HEXALGON SSO Local")
    sso_client_id: str = os.getenv("HEXALGON_SSO_CLIENT_ID", "hexalgon-iam-broker")
    sso_client_secret: str = os.getenv("HEXALGON_SSO_CLIENT_SECRET", "hexalgon-iam-broker-secret")
    sso_test_user_email: str = os.getenv("HEXALGON_SSO_TEST_USER_EMAIL", "federated.user@federation-sandbox.example.com")
    sso_test_user_password: str = os.getenv("HEXALGON_SSO_TEST_USER_PASSWORD", "HexalgonUser123!")
    sso_test_user_first_name: str = os.getenv("HEXALGON_SSO_TEST_USER_FIRST_NAME", "Federated")
    sso_test_user_last_name: str = os.getenv("HEXALGON_SSO_TEST_USER_LAST_NAME", "User")
    seed_upstream_user: bool = _env_flag("SEED_UPSTREAM_USER", True)


def _candidate_discovery_urls(sso_base_url: str) -> list[str]:
    base_url = _normalized_base_url(sso_base_url)
    return [
        f"{base_url}/api/v1/.well-known/openid-configuration",
        f"{base_url}/.well-known/openid-configuration",
    ]


async def _fetch_discovery(client: httpx.AsyncClient, sso_base_url: str) -> tuple[dict[str, Any], str]:
    last_error: httpx.HTTPError | None = None
    for discovery_url in _candidate_discovery_urls(sso_base_url):
        try:
            response = await client.get(discovery_url, headers={"Accept": "application/json"})
            response.raise_for_status()
            return response.json(), discovery_url
        except httpx.HTTPError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise RuntimeError("No discovery URLs were generated")


async def _register_upstream_client(
    client: httpx.AsyncClient,
    *,
    sso_base_url: str,
    fallback_client_id: str,
    fallback_client_secret: str,
    callback_uri: str,
) -> dict[str, Any]:
    generate_url = f"{_normalized_base_url(sso_base_url)}/dev/clients/generate"
    fallback_url = f"{_normalized_base_url(sso_base_url)}/dev/clients"

    try:
        response = await client.post(
            generate_url,
            json={
                "name": "HEX IAM Federation Broker",
                "redirect_uri": callback_uri,
            },
        )
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code != 404:
            raise

    response = await client.post(
        fallback_url,
        json={
            "client_id": fallback_client_id,
            "client_secret": fallback_client_secret,
            "name": "HEX IAM Federation Broker",
            "redirect_uri": callback_uri,
        },
    )
    response.raise_for_status()
    data = response.json()
    data.setdefault("client_secret", fallback_client_secret)
    return data


def _extract_api_data(response: httpx.Response) -> Any:
    body = response.json()
    if isinstance(body, dict) and "data" in body:
        return body["data"]
    return body


async def _authenticate_iam_admin(client: httpx.AsyncClient, config: SeedConfig) -> str:
    response = await client.post(
        f"{_normalized_base_url(config.iam_base_url)}/api/v1/authenticate/token",
        headers={"X-TENANT-ID": config.tenant_id},
        json={
            "email": config.admin_email,
            "password": config.admin_password,
        },
    )
    response.raise_for_status()
    data = _extract_api_data(response)
    access_token = data.get("access_token") if isinstance(data, dict) else None
    if not access_token:
        raise RuntimeError("IAM token response did not contain access_token")
    return access_token


async def _upsert_iam_oidc_client(
    client: httpx.AsyncClient,
    *,
    config: SeedConfig,
    access_token: str,
) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-TENANT-ID": config.tenant_id,
    }
    desired_redirect_uris = [config.oidc_client_redirect_uri]
    desired_scopes = ["openid", "profile", "email"]

    list_response = await client.get(
        f"{_normalized_base_url(config.iam_base_url)}/api/v1/oidc/clients",
        headers=headers,
    )
    list_response.raise_for_status()
    existing_clients = _extract_api_data(list_response) or []
    if not isinstance(existing_clients, list):
        raise RuntimeError("Unexpected IAM clients list response shape")

    existing_client = None
    if config.oidc_client_id:
        existing_client = next(
            (c for c in existing_clients if c.get("client_id") == config.oidc_client_id),
            None,
        )
    if not existing_client:
        existing_client = next(
            (
                c for c in existing_clients
                if c.get("name") == config.oidc_client_name
            ),
            None,
        )

    if existing_client:
        client_id = existing_client.get("client_id")
        if not client_id:
            raise RuntimeError("Existing IAM OIDC client is missing client_id")

        patch_response = await client.patch(
            f"{_normalized_base_url(config.iam_base_url)}/api/v1/oidc/clients/{client_id}",
            headers=headers,
            json={
                "name": config.oidc_client_name,
                "redirect_uris": desired_redirect_uris,
                "scopes": desired_scopes,
            },
        )
        patch_response.raise_for_status()

        rotate_response = await client.post(
            f"{_normalized_base_url(config.iam_base_url)}/api/v1/oidc/clients/{client_id}/rotate-secret",
            headers=headers,
        )
        rotate_response.raise_for_status()
        rotated = _extract_api_data(rotate_response)
        secret = rotated.get("client_secret") if isinstance(rotated, dict) else None
        if not secret:
            raise RuntimeError("IAM rotate-secret response did not contain client_secret")
        return {
            "client_id": client_id,
            "client_secret": secret,
            "status": "rotated",
        }

    create_response = await client.post(
        f"{_normalized_base_url(config.iam_base_url)}/api/v1/oidc/clients",
        headers=headers,
        json={
            "name": config.oidc_client_name,
            "redirect_uris": desired_redirect_uris,
            "scopes": desired_scopes,
        },
    )
    create_response.raise_for_status()
    created = _extract_api_data(create_response)
    client_id = created.get("client_id") if isinstance(created, dict) else None
    client_secret = created.get("client_secret") if isinstance(created, dict) else None
    if not client_id or not client_secret:
        raise RuntimeError("IAM client create response did not contain client_id/client_secret")
    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "status": "created",
    }


async def _maybe_seed_upstream_user(client: httpx.AsyncClient, config: SeedConfig) -> dict[str, str]:
    if not config.seed_upstream_user:
        return {"status": "skipped", "detail": "SEED_UPSTREAM_USER=false"}

    try:
        response = await client.post(
            f"{_normalized_base_url(config.sso_base_url)}/dev/users",
            json={
                "email": config.sso_test_user_email,
                "password": config.sso_test_user_password,
                "first_name": config.sso_test_user_first_name,
                "last_name": config.sso_test_user_last_name,
            },
        )
        response.raise_for_status()
        return {"status": "created", "detail": config.sso_test_user_email}
    except httpx.HTTPStatusError as exc:
        detail = exc.response.text.strip() or exc.response.reason_phrase
        return {"status": "exists_or_failed", "detail": detail}


async def _resolve_admin_user_id(conn: asyncpg.Connection, config: SeedConfig) -> str:
    existing_user_id = await conn.fetchval(
        "SELECT id FROM users WHERE tenant_id = $1 AND email = $2",
        config.tenant_id,
        config.admin_email,
    )
    return existing_user_id or config.admin_user_id


async def _resolve_provider_id(conn: asyncpg.Connection, tenant_id: str, issuer_url: str, default_provider_id: str) -> str:
    existing_provider_id = await conn.fetchval(
        "SELECT id FROM identity_providers WHERE tenant_id = $1 AND issuer_url = $2",
        tenant_id,
        issuer_url,
    )
    return existing_provider_id or default_provider_id


async def _ensure_seed_data(
    conn: asyncpg.Connection,
    *,
    config: SeedConfig,
    discovery: dict[str, Any],
    discovery_url: str,
    provider_id: str,
    upstream_client: dict[str, Any],
) -> dict[str, Any]:
    admin_user_id = await _resolve_admin_user_id(conn, config)
    admin_password_hash = await asyncio.to_thread(hash_password, config.admin_password)

    existing_tenant_id = await conn.fetchval("SELECT id FROM tenants WHERE domain = $1", config.tenant_domain)
    if existing_tenant_id and existing_tenant_id != config.tenant_id:
        raise RuntimeError(
            f"Tenant domain '{config.tenant_domain}' already belongs to tenant '{existing_tenant_id}'. "
            f"Pick a different FEDERATION_TEST_TENANT_DOMAIN or tenant id."
        )

    async with conn.transaction():
        await conn.execute(
            """
            INSERT INTO tenants (id, name, domain, root, settings, is_active)
            VALUES ($1, $2, $3, $4, $5::jsonb, TRUE)
            ON CONFLICT (id) DO UPDATE
            SET name = EXCLUDED.name,
                domain = EXCLUDED.domain,
                root = EXCLUDED.root,
                settings = EXCLUDED.settings,
                is_active = TRUE
            """,
            config.tenant_id,
            config.tenant_name,
            config.tenant_domain,
            config.admin_email,
            json.dumps({"mfa_enabled": False}),
        )

        await conn.execute(
            """
            INSERT INTO users (
                id, tenant_id, email, password, first_name, last_name,
                role, is_active, email_verified
            )
            VALUES ($1, $2, $3, $4, $5, $6, 'admin', TRUE, TRUE)
            ON CONFLICT (id) DO UPDATE
            SET email = EXCLUDED.email,
                password = EXCLUDED.password,
                first_name = EXCLUDED.first_name,
                last_name = EXCLUDED.last_name,
                role = EXCLUDED.role,
                is_active = TRUE,
                email_verified = TRUE,
                last_modified = NOW()
            """,
            admin_user_id,
            config.tenant_id,
            config.admin_email,
            admin_password_hash,
            config.admin_first_name,
            config.admin_last_name,
        )

        for resource in ADMIN_POLICY_RESOURCES:
            await conn.execute(
                """
                INSERT INTO user_policies (tenant_id, user_id, policy_id, policy)
                VALUES ($1, $2, $3, $4::jsonb)
                ON CONFLICT (tenant_id, user_id, policy_id) DO UPDATE
                SET policy = EXCLUDED.policy,
                    last_modified = NOW()
                """,
                config.tenant_id,
                admin_user_id,
                f"seed-admin-{resource}",
                _admin_policy(resource),
            )

        await conn.execute(
            """
            INSERT INTO identity_providers (
                id, tenant_id, name, protocol, issuer_url, client_id, client_secret,
                discovery_url, authorization_endpoint, token_endpoint, userinfo_endpoint,
                jwks_uri, enabled, auto_link, authorization_scopes, token_endpoint_auth_method,
                claims_source, link_by_email_verified_only, default_role
            )
            VALUES (
                $1, $2, $3, 'oidc', $4, $5, $6,
                $7, $8, $9, $10,
                $11, TRUE, TRUE, 'openid profile email', 'client_secret_post',
                'auto', TRUE, 'member'
            )
            ON CONFLICT (id) DO UPDATE
            SET tenant_id = EXCLUDED.tenant_id,
                name = EXCLUDED.name,
                issuer_url = EXCLUDED.issuer_url,
                client_id = EXCLUDED.client_id,
                client_secret = EXCLUDED.client_secret,
                discovery_url = EXCLUDED.discovery_url,
                authorization_endpoint = EXCLUDED.authorization_endpoint,
                token_endpoint = EXCLUDED.token_endpoint,
                userinfo_endpoint = EXCLUDED.userinfo_endpoint,
                jwks_uri = EXCLUDED.jwks_uri,
                enabled = TRUE,
                auto_link = TRUE,
                authorization_scopes = EXCLUDED.authorization_scopes,
                token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method,
                claims_source = EXCLUDED.claims_source,
                link_by_email_verified_only = TRUE,
                default_role = EXCLUDED.default_role,
                last_modified = NOW()
            """,
            provider_id,
            config.tenant_id,
            config.provider_name,
            discovery["issuer"],
            upstream_client["client_id"],
            upstream_client["client_secret"],
            discovery_url,
            discovery.get("authorization_endpoint"),
            discovery.get("token_endpoint"),
            discovery.get("userinfo_endpoint"),
            discovery.get("jwks_uri"),
        )

    return {
        "tenant_id": config.tenant_id,
        "admin_user_id": admin_user_id,
        "provider_id": provider_id,
    }


async def main() -> None:
    config = SeedConfig(
        iam_base_url=_normalized_base_url(os.getenv("IAM_APP_BASE_URL", APP_BASE_URL)),
        sso_base_url=_normalized_base_url(os.getenv("HEXALGON_SSO_BASE_URL", "http://localhost:8100")),
    )

    async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as http_client:
        try:
            discovery, discovery_url = await _fetch_discovery(http_client, config.sso_base_url)
        except httpx.HTTPError as exc:
            raise RuntimeError(
                f"Unable to reach hexalgon-sso discovery at any of: "
                f"{', '.join(_candidate_discovery_urls(config.sso_base_url))}. "
                f"Make sure the SSO app is running and HEXALGON_SSO_BASE_URL is correct."
            ) from exc

        conn = await asyncpg.connect(db_owner_connection_string)
        try:
            provider_id = await _resolve_provider_id(conn, config.tenant_id, discovery["issuer"], config.provider_id)
            callback_uri = _provider_callback_uri(config.iam_base_url, provider_id)
            upstream_client = await _register_upstream_client(
                http_client,
                sso_base_url=config.sso_base_url,
                fallback_client_id=config.sso_client_id,
                fallback_client_secret=config.sso_client_secret,
                callback_uri=callback_uri,
            )
            upstream_user = await _maybe_seed_upstream_user(http_client, config)
            seed_result = await _ensure_seed_data(
                conn,
                config=config,
                discovery=discovery,
                discovery_url=discovery_url,
                provider_id=provider_id,
                upstream_client=upstream_client,
            )
        finally:
            await conn.close()

        try:
            access_token = await _authenticate_iam_admin(http_client, config)
            iam_oidc_client = await _upsert_iam_oidc_client(
                http_client,
                config=config,
                access_token=access_token,
            )
        except httpx.HTTPError as exc:
            raise RuntimeError(
                "Unable to create IAM OIDC client via API. "
                "Make sure HEX IAM is running and IAM_APP_BASE_URL is correct."
            ) from exc

    authorize_url = (
        f"{config.iam_base_url}/api/v1/oidc/authorize"
        f"?client_id={iam_oidc_client['client_id']}"
        f"&redirect_uri={config.oidc_client_redirect_uri}"
        f"&response_type=code"
        f"&scope=openid%20profile%20email"
    )

    print("Federation sandbox seeded.")
    print(f"IAM tenant: {seed_result['tenant_id']}")
    print(f"IAM admin: {config.admin_email} / {config.admin_password}")
    print(
        f"IAM OIDC client ({iam_oidc_client['status']}): "
        f"{iam_oidc_client['client_id']} / {iam_oidc_client['client_secret']}"
    )
    print(f"Upstream provider id: {seed_result['provider_id']}")
    print(f"Upstream broker client: {upstream_client['client_id']} / {upstream_client['client_secret']} -> {callback_uri}")
    print(f"Upstream test user: {upstream_user['status']} ({upstream_user['detail']})")
    print(f"Discovery issuer: {discovery['issuer']}")
    print(f"Authorize URL: {authorize_url}")


if __name__ == "__main__":
    asyncio.run(main())
