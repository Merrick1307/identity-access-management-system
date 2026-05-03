import base64
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Optional
from uuid import uuid4
from urllib.parse import urlencode

import asyncpg
import httpx
import jwt
import orjson
import redis

from app.core.security import hash_password


_DISCOVERY_CACHE: dict[str, dict[str, Any]] = {}


@dataclass
class BrokerValidationResult:
    provider: dict[str, Any]
    claims: dict[str, Any]


async def list_identity_providers(db: asyncpg.Connection, tenant_id: str, redis_conn: Optional[redis.Redis] = None):
    if redis_conn:
        cached = await redis_conn.get(f"fed_providers:{tenant_id}")
        if cached:
            return orjson.loads(cached)
    rows = await db.fetch(
        """
        SELECT id, tenant_id, name, protocol, issuer_url, client_id, discovery_url,
               authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri,
               enabled, auto_link, authorization_scopes, token_endpoint_auth_method,
               claims_source, link_by_email_verified_only, default_role,
               created_at, last_modified
        FROM identity_providers
        WHERE tenant_id = $1
        ORDER BY created_at DESC
        """,
        tenant_id,
    )
    result = []
    for r in rows:
        d = dict(r)
        d["created_at"] = d["created_at"].isoformat() if d["created_at"] else None
        d["last_modified"] = d["last_modified"].isoformat() if d["last_modified"] else None
        result.append(d)
    if redis_conn:
        await redis_conn.setex(f"fed_providers:{tenant_id}", 60, orjson.dumps(result))
    return result


async def get_identity_provider(db: asyncpg.Connection, tenant_id: str, provider_id: str):
    row = await db.fetchrow("SELECT * FROM identity_providers WHERE tenant_id = $1 AND id = $2", tenant_id, provider_id)
    return dict(row) if row else None


async def create_identity_provider(db: asyncpg.Connection, tenant_id: str, payload: dict[str, Any], redis_conn: Optional[redis.Redis] = None):
    if payload.get('protocol', 'oidc') != 'oidc':
        raise ValueError('Only OIDC identity providers are supported right now')
    provider_id = str(uuid4())
    await db.execute(
        """
        INSERT INTO identity_providers (
            id, tenant_id, name, protocol, issuer_url, client_id, client_secret,
            discovery_url, authorization_endpoint, token_endpoint, userinfo_endpoint,
            jwks_uri, jwt_validation_secret, enabled, auto_link, authorization_scopes,
            token_endpoint_auth_method, claims_source, link_by_email_verified_only, default_role
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,
            $8,$9,$10,$11,
            $12,$13,$14,$15,$16,
            $17,$18,$19,$20
        )
        """,
        provider_id, tenant_id, payload.get('name'), payload.get('protocol', 'oidc'), payload.get('issuer_url'), payload.get('client_id'), payload.get('client_secret'),
        payload.get('discovery_url'), payload.get('authorization_endpoint'), payload.get('token_endpoint'), payload.get('userinfo_endpoint'),
        payload.get('jwks_uri'), payload.get('jwt_validation_secret'), payload.get('enabled', True), payload.get('auto_link', True), payload.get('authorization_scopes', 'openid profile email'),
        payload.get('token_endpoint_auth_method', 'client_secret_post'), payload.get('claims_source', 'auto'), payload.get('link_by_email_verified_only', True), payload.get('default_role', 'member'),
    )
    if redis_conn:
        await redis_conn.delete(f"fed_providers:{tenant_id}")
    return await get_identity_provider(db, tenant_id, provider_id)


async def update_identity_provider(
        db: asyncpg.Connection, tenant_id: str,
        provider_id: str, payload: dict[str, Any],
        redis_conn: Optional[redis.Redis] = None
):
    current = await get_identity_provider(db, tenant_id, provider_id)
    if not current:
        return None
    merged = {**current, **payload}
    if merged.get('protocol') != 'oidc':
        raise ValueError('Only OIDC identity providers are supported right now')
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
            authorization_scopes = $16,
            token_endpoint_auth_method = $17,
            claims_source = $18,
            link_by_email_verified_only = $19,
            default_role = $20,
            last_modified = NOW()
        WHERE tenant_id = $1 AND id = $2
        """,
        tenant_id, provider_id, merged.get('name'), merged.get('protocol'), merged.get('issuer_url'), merged.get('client_id'), merged.get('client_secret'), merged.get('discovery_url'), merged.get('authorization_endpoint'), merged.get('token_endpoint'), merged.get('userinfo_endpoint'), merged.get('jwks_uri'), merged.get('jwt_validation_secret'), merged.get('enabled', True), merged.get('auto_link', True), merged.get('authorization_scopes', 'openid profile email'), merged.get('token_endpoint_auth_method', 'client_secret_post'), merged.get('claims_source', 'auto'), merged.get('link_by_email_verified_only', True), merged.get('default_role', 'member')
    )
    _DISCOVERY_CACHE.pop(merged.get('discovery_url') or merged.get('issuer_url'), None)
    if redis_conn:
        await redis_conn.delete(f"fed_providers:{tenant_id}")
    return await get_identity_provider(db, tenant_id, provider_id)


async def delete_identity_provider(db: asyncpg.Connection, tenant_id: str, provider_id: str, redis_conn: Optional[redis.Redis] = None) -> bool:
    result = await db.execute("DELETE FROM identity_providers WHERE tenant_id = $1 AND id = $2", tenant_id, provider_id)
    if redis_conn:
        await redis_conn.delete(f"fed_providers:{tenant_id}")
    return result.endswith('1')


async def list_federated_links_for_provider(db: asyncpg.Connection, tenant_id: str, provider_id: str):
    rows = await db.fetch(
        """
        SELECT id, tenant_id, provider_id, user_id, external_subject, external_email, created_at
        FROM federated_identities
        WHERE tenant_id = $1 AND provider_id = $2
        ORDER BY created_at DESC
        """,
        tenant_id, provider_id,
    )
    return [dict(r) for r in rows]


async def _resolve_discovery(provider: dict[str, Any]) -> dict[str, Any]:
    cache_key = provider.get('discovery_url') or provider.get('issuer_url')
    if cache_key in _DISCOVERY_CACHE:
        return _DISCOVERY_CACHE[cache_key]
    discovery_url = provider.get('discovery_url') or provider.get('issuer_url', '').rstrip('/') + '/.well-known/openid-configuration'
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(discovery_url, headers={'Accept': 'application/json'})
        response.raise_for_status()
        data = response.json()
    _DISCOVERY_CACHE[cache_key] = data
    return data


async def _verify_jwt(subject_token: str, provider: dict[str, Any], audience: str) -> dict[str, Any]:
    issuer = provider['issuer_url']
    jwt_validation_secret = provider.get('jwt_validation_secret')
    if jwt_validation_secret:
        return jwt.decode(subject_token, jwt_validation_secret, algorithms=['HS256', 'HS384', 'HS512'], audience=audience, issuer=issuer)
    jwks_uri = provider.get('jwks_uri')
    if not jwks_uri:
        discovery = await _resolve_discovery(provider)
        jwks_uri = discovery.get('jwks_uri')
    if not jwks_uri:
        raise jwt.InvalidTokenError('Provider missing jwks_uri and jwt_validation_secret')
    signing_key = jwt.PyJWKClient(jwks_uri).get_signing_key_from_jwt(subject_token)
    return jwt.decode(subject_token, signing_key.key, algorithms=['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'], audience=audience, issuer=issuer)


async def validate_broker_subject_token(db: asyncpg.Connection, tenant_id: str, subject_token: str, audience: str, issuer_hint: Optional[str] = None) -> Optional[BrokerValidationResult]:
    unverified = jwt.decode(subject_token, options={'verify_signature': False, 'verify_aud': False})
    issuer = issuer_hint or unverified.get('iss')
    if not issuer:
        return None
    row = await db.fetchrow(
        """
        SELECT * FROM identity_providers
        WHERE tenant_id = $1 AND issuer_url = $2 AND enabled = TRUE AND protocol = 'oidc'
        """,
        tenant_id, issuer,
    )
    if not row:
        return None
    provider = dict(row)
    claims = await _verify_jwt(subject_token, provider, audience)
    return BrokerValidationResult(provider=provider, claims=claims)


def _normalized_email_verified(claims: dict[str, Any]) -> bool:
    value = claims.get('email_verified')
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() == 'true'
    return bool(value)


async def _find_or_create_local_user(db: asyncpg.Connection, tenant_id: str, provider: dict[str, Any], claims: dict[str, Any]) -> dict[str, Any]:
    external_subject = claims['sub']
    external_email = claims.get('email')
    email_verified = _normalized_email_verified(claims)
    link = await db.fetchrow(
        """
        SELECT fi.id AS link_id, u.*
        FROM federated_identities fi
        JOIN users u ON u.id = fi.user_id
        WHERE fi.tenant_id = $1 AND fi.provider_id = $2 AND fi.external_subject = $3
        """,
        tenant_id, provider['id'], external_subject,
    )
    if link:
        return dict(link)

    if not provider.get('auto_link', True):
        raise ValueError('Federated account is not linked to a local user yet')

    user = None
    if external_email:
        user = await db.fetchrow('SELECT * FROM users WHERE tenant_id = $1 AND email = $2', tenant_id, external_email)
        if user and provider.get('link_by_email_verified_only', True) and not email_verified:
            raise ValueError('Provider email must be verified before auto-linking to an existing user')

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
            user_id, tenant_id, email, random_password, first_name, last_name or 'User', provider.get('default_role', 'member'), email_verified or bool(external_email),
        )
        user = await db.fetchrow('SELECT * FROM users WHERE id = $1', user_id)

    await db.execute(
        """
        INSERT INTO federated_identities (id, tenant_id, provider_id, user_id, external_subject, external_email)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (tenant_id, provider_id, external_subject)
        DO UPDATE SET external_email = EXCLUDED.external_email
        """,
        str(uuid4()), tenant_id, provider['id'], user['id'], external_subject, external_email,
    )
    return dict(user)


async def resolve_or_provision_federated_user(db: asyncpg.Connection, tenant_id: str, subject_token: str, audience: str, issuer_hint: Optional[str] = None) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    result = await validate_broker_subject_token(db, tenant_id, subject_token, audience, issuer_hint)
    if not result:
        raise ValueError('No enabled identity provider matched the broker token issuer')
    user = await _find_or_create_local_user(db, tenant_id, result.provider, result.claims)
    return user, result.provider, result.claims


async def list_enabled_identity_providers(db: asyncpg.Connection, tenant_id: str, protocol: str = 'oidc') -> list[dict[str, Any]]:
    rows = await db.fetch(
        """
        SELECT * FROM identity_providers
        WHERE tenant_id = $1 AND enabled = TRUE AND protocol = $2
        ORDER BY created_at ASC
        """,
        tenant_id, protocol,
    )
    return [dict(r) for r in rows]


async def create_federation_auth_transaction(
        db: asyncpg.Connection, *, tenant_id: str, provider_id: str, client_id: str,
        redirect_uri: str, scope: str, state: Optional[str], nonce: Optional[str],
        code_challenge: Optional[str], code_challenge_method: Optional[str],
        upstream_state: str, upstream_nonce: Optional[str],
        expires_in_seconds: int = 600
) -> dict[str, Any]:
    transaction_id = str(uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds)
    await db.execute(
        """
        INSERT INTO federation_auth_transactions (
            id, tenant_id, provider_id, client_id, redirect_uri, scope, state, nonce,
            code_challenge, code_challenge_method, upstream_state, upstream_nonce, expires_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8,
            $9, $10, $11, $12, $13
        )
        """,
        transaction_id, tenant_id, provider_id, client_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method, upstream_state, upstream_nonce, expires_at,
    )
    row = await db.fetchrow('SELECT * FROM federation_auth_transactions WHERE id = $1', transaction_id)
    return dict(row) if row else {'id': transaction_id, 'upstream_state': upstream_state}


async def get_federation_auth_transaction_by_state(db: asyncpg.Connection, *, provider_id: str, upstream_state: str) -> Optional[dict[str, Any]]:
    row = await db.fetchrow(
        """
        SELECT * FROM federation_auth_transactions
        WHERE provider_id = $1 AND upstream_state = $2 AND consumed_at IS NULL AND expires_at > NOW()
        """,
        provider_id, upstream_state,
    )
    return dict(row) if row else None


async def consume_federation_auth_transaction(db: asyncpg.Connection, transaction_id: str) -> None:
    await db.execute('UPDATE federation_auth_transactions SET consumed_at = NOW() WHERE id = $1', transaction_id)


async def build_provider_authorize_url(provider: dict[str, Any], *, redirect_uri: str, upstream_state: str, upstream_nonce: Optional[str]) -> str:
    authorization_endpoint = provider.get('authorization_endpoint')
    if not authorization_endpoint:
        discovery = await _resolve_discovery(provider)
        authorization_endpoint = discovery.get('authorization_endpoint')
    if not authorization_endpoint:
        raise ValueError('Provider missing authorization endpoint')
    params = {
        'client_id': provider.get('client_id'),
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': provider.get('authorization_scopes') or 'openid profile email',
        'state': upstream_state,
    }
    if upstream_nonce:
        params['nonce'] = upstream_nonce
    return f"{authorization_endpoint}?{urlencode(params)}"


async def exchange_code_for_provider_tokens(provider: dict[str, Any], *, code: str, redirect_uri: str) -> dict[str, Any]:
    token_endpoint = provider.get('token_endpoint')
    if not token_endpoint:
        discovery = await _resolve_discovery(provider)
        token_endpoint = discovery.get('token_endpoint')
    if not token_endpoint:
        raise ValueError('Provider missing token endpoint')
    form = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri,
        'client_id': provider.get('client_id'),
    }
    headers = {'Accept': 'application/json'}
    client_secret = provider.get('client_secret')
    method = provider.get('token_endpoint_auth_method') or 'client_secret_post'
    if method == 'client_secret_basic' and client_secret:
        basic = base64.b64encode(f"{provider.get('client_id')}:{client_secret}".encode()).decode()
        headers['Authorization'] = f'Basic {basic}'
    elif client_secret:
        form['client_secret'] = client_secret
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(token_endpoint, data=form, headers=headers)
        response.raise_for_status()
        return response.json()


async def fetch_userinfo(provider: dict[str, Any], *, access_token: str) -> dict[str, Any]:
    userinfo_endpoint = provider.get('userinfo_endpoint')
    if not userinfo_endpoint:
        discovery = await _resolve_discovery(provider)
        userinfo_endpoint = discovery.get('userinfo_endpoint')
    if not userinfo_endpoint:
        raise ValueError('Provider missing userinfo endpoint')
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(userinfo_endpoint, headers={'Authorization': f'Bearer {access_token}', 'Accept': 'application/json'})
        response.raise_for_status()
        return response.json()


async def resolve_or_provision_from_provider_tokens(db: asyncpg.Connection, *, tenant_id: str, provider: dict[str, Any], tokens: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    claims_source = provider.get('claims_source') or 'auto'
    id_token = tokens.get('id_token')
    access_token = tokens.get('access_token')
    claims: dict[str, Any] | None = None
    if claims_source in ('auto', 'id_token') and id_token:
        claims = await _verify_jwt(id_token, provider, provider.get('client_id'))
    if claims is None and claims_source in ('auto', 'userinfo') and access_token:
        claims = await fetch_userinfo(provider, access_token=access_token)
        claims.setdefault('iss', provider.get('issuer_url'))
    if claims is None:
        raise ValueError('Provider did not return usable identity claims')
    user = await _find_or_create_local_user(db, tenant_id, provider, claims)
    return user, claims
