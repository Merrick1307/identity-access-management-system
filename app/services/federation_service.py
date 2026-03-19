import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

import asyncpg
import httpx
import jwt

from app.core.security import hash_password


_DISCOVERY_CACHE: dict[str, dict[str, Any]] = {}


@dataclass
class BrokerValidationResult:
    provider: dict[str, Any]
    claims: dict[str, Any]


async def list_identity_providers(db: asyncpg.Connection, tenant_id: str):
    rows = await db.fetch(
        """
        SELECT id, tenant_id, name, protocol, issuer_url, client_id, discovery_url,
               authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri,
               enabled, auto_link, created_at, last_modified
        FROM identity_providers
        WHERE tenant_id = $1
        ORDER BY created_at DESC
        """,
        tenant_id,
    )
    return [dict(r) for r in rows]


async def get_identity_provider(db: asyncpg.Connection, tenant_id: str, provider_id: str):
    row = await db.fetchrow(
        """
        SELECT * FROM identity_providers
        WHERE tenant_id = $1 AND id = $2
        """,
        tenant_id,
        provider_id,
    )
    return dict(row) if row else None


async def create_identity_provider(db: asyncpg.Connection, tenant_id: str, payload: dict[str, Any]):
    provider_id = str(uuid4())
    await db.execute(
        """
        INSERT INTO identity_providers (
            id, tenant_id, name, protocol, issuer_url, client_id, client_secret,
            discovery_url, authorization_endpoint, token_endpoint, userinfo_endpoint,
            jwks_uri, jwt_validation_secret, enabled, auto_link
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9, $10, $11,
            $12, $13, $14, $15
        )
        """,
        provider_id,
        tenant_id,
        payload.get('name'),
        payload.get('protocol', 'oidc'),
        payload.get('issuer_url'),
        payload.get('client_id'),
        payload.get('client_secret'),
        payload.get('discovery_url'),
        payload.get('authorization_endpoint'),
        payload.get('token_endpoint'),
        payload.get('userinfo_endpoint'),
        payload.get('jwks_uri'),
        payload.get('jwt_validation_secret'),
        payload.get('enabled', True),
        payload.get('auto_link', True),
    )
    return await get_identity_provider(db, tenant_id, provider_id)


async def update_identity_provider(db: asyncpg.Connection, tenant_id: str, provider_id: str, payload: dict[str, Any]):
    current = await get_identity_provider(db, tenant_id, provider_id)
    if not current:
        return None
    merged = {**current, **payload}
    await db.execute(
        """
        UPDATE identity_providers
        SET name = $3,
            protocol = $4,
            issuer_url = $5,
            client_id = $6,
            client_secret = $7,
            discovery_url = $8,
            authorization_endpoint = $9,
            token_endpoint = $10,
            userinfo_endpoint = $11,
            jwks_uri = $12,
            jwt_validation_secret = $13,
            enabled = $14,
            auto_link = $15,
            last_modified = NOW()
        WHERE tenant_id = $1 AND id = $2
        """,
        tenant_id,
        provider_id,
        merged.get('name'),
        merged.get('protocol'),
        merged.get('issuer_url'),
        merged.get('client_id'),
        merged.get('client_secret'),
        merged.get('discovery_url'),
        merged.get('authorization_endpoint'),
        merged.get('token_endpoint'),
        merged.get('userinfo_endpoint'),
        merged.get('jwks_uri'),
        merged.get('jwt_validation_secret'),
        merged.get('enabled', True),
        merged.get('auto_link', True),
    )
    return await get_identity_provider(db, tenant_id, provider_id)


async def delete_identity_provider(db: asyncpg.Connection, tenant_id: str, provider_id: str) -> bool:
    result = await db.execute(
        "DELETE FROM identity_providers WHERE tenant_id = $1 AND id = $2",
        tenant_id,
        provider_id,
    )
    return result.endswith('1')


async def list_federated_links_for_provider(db: asyncpg.Connection, tenant_id: str, provider_id: str):
    rows = await db.fetch(
        """
        SELECT id, tenant_id, provider_id, user_id, external_subject, external_email, created_at
        FROM federated_identities
        WHERE tenant_id = $1 AND provider_id = $2
        ORDER BY created_at DESC
        """,
        tenant_id,
        provider_id,
    )
    return [dict(r) for r in rows]


async def _resolve_discovery(provider: dict[str, Any]) -> dict[str, Any]:
    cache_key = provider.get('discovery_url') or provider.get('issuer_url')
    if cache_key in _DISCOVERY_CACHE:
        return _DISCOVERY_CACHE[cache_key]
    discovery_url = provider.get('discovery_url') or provider.get('issuer_url', '').rstrip('/') + '/.well-known/openid-configuration'
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(discovery_url)
        response.raise_for_status()
        data = response.json()
    _DISCOVERY_CACHE[cache_key] = data
    return data


async def _verify_subject_token(subject_token: str, provider: dict[str, Any], audience: str) -> dict[str, Any]:
    issuer = provider['issuer_url']
    jwt_validation_secret = provider.get('jwt_validation_secret')
    if jwt_validation_secret:
        return jwt.decode(
            subject_token,
            jwt_validation_secret,
            algorithms=['HS256', 'HS384', 'HS512'],
            audience=audience,
            issuer=issuer,
        )

    jwks_uri = provider.get('jwks_uri')
    if not jwks_uri:
        discovery = await _resolve_discovery(provider)
        jwks_uri = discovery.get('jwks_uri')
    if not jwks_uri:
        raise jwt.InvalidTokenError('Provider missing jwks_uri and jwt_validation_secret')

    signing_key = jwt.PyJWKClient(jwks_uri).get_signing_key_from_jwt(subject_token)
    return jwt.decode(
        subject_token,
        signing_key.key,
        algorithms=['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'],
        audience=audience,
        issuer=issuer,
    )


async def validate_broker_subject_token(
    db: asyncpg.Connection,
    tenant_id: str,
    subject_token: str,
    audience: str,
    issuer_hint: Optional[str] = None,
) -> Optional[BrokerValidationResult]:
    unverified = jwt.decode(subject_token, options={"verify_signature": False, "verify_aud": False})
    issuer = issuer_hint or unverified.get('iss')
    if not issuer:
        return None
    row = await db.fetchrow(
        """
        SELECT * FROM identity_providers
        WHERE tenant_id = $1 AND issuer_url = $2 AND enabled = TRUE AND protocol = 'oidc'
        """,
        tenant_id,
        issuer,
    )
    if not row:
        return None
    provider = dict(row)
    claims = await _verify_subject_token(subject_token, provider, audience)
    return BrokerValidationResult(provider=provider, claims=claims)


async def _find_or_create_local_user(db: asyncpg.Connection, tenant_id: str, provider: dict[str, Any], claims: dict[str, Any]) -> dict[str, Any]:
    external_subject = claims['sub']
    external_email = claims.get('email')
    link = await db.fetchrow(
        """
        SELECT fi.id AS link_id, u.*
        FROM federated_identities fi
        JOIN users u ON u.id = fi.user_id
        WHERE fi.tenant_id = $1 AND fi.provider_id = $2 AND fi.external_subject = $3
        """,
        tenant_id,
        provider['id'],
        external_subject,
    )
    if link:
        return dict(link)

    if not provider.get('auto_link', True):
        raise ValueError('Federated account is not linked to a local user yet')

    user = None
    if external_email:
        user = await db.fetchrow(
            "SELECT * FROM users WHERE tenant_id = $1 AND email = $2",
            tenant_id,
            external_email,
        )

    if not user:
        user_id = str(uuid4())
        name = claims.get('name') or ''
        first_name = claims.get('given_name') or (name.split(' ')[0] if name else 'Federated')
        last_name = claims.get('family_name') or (' '.join(name.split(' ')[1:]) if len(name.split(' ')) > 1 else 'User')
        email = external_email or f"federated-{external_subject}@{tenant_id}.local"
        random_password = hash_password(secrets.token_urlsafe(24))
        await db.execute(
            """
            INSERT INTO users (id, tenant_id, email, password, first_name, last_name, role, is_active, email_verified)
            VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, $8)
            """,
            user_id,
            tenant_id,
            email,
            random_password,
            first_name,
            last_name or 'User',
            'member',
            claims.get('email_verified', bool(external_email)),
        )
        user = await db.fetchrow("SELECT * FROM users WHERE id = $1", user_id)

    await db.execute(
        """
        INSERT INTO federated_identities (id, tenant_id, provider_id, user_id, external_subject, external_email)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (tenant_id, provider_id, external_subject)
        DO UPDATE SET external_email = EXCLUDED.external_email
        """,
        str(uuid4()),
        tenant_id,
        provider['id'],
        user['id'],
        external_subject,
        external_email,
    )
    return dict(user)


async def resolve_or_provision_federated_user(
    db: asyncpg.Connection,
    tenant_id: str,
    subject_token: str,
    audience: str,
    issuer_hint: Optional[str] = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    result = await validate_broker_subject_token(db, tenant_id, subject_token, audience, issuer_hint)
    if not result:
        raise ValueError('No enabled identity provider matched the broker token issuer')
    user = await _find_or_create_local_user(db, tenant_id, result.provider, result.claims)
    return user, result.provider, result.claims
