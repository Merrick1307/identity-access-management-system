# FILE: app/services/oidc_service.py

import hashlib
import secrets
import base64
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
import asyncpg
import bcrypt

from app.core.jwt_utils import create_jwt_token
from app.core.config import JWT_SECRET


class OIDCService:
    """Service for handling OIDC operations"""

    @staticmethod
    async def validate_client(
            db: asyncpg.Connection,
            client_id: str,
            client_secret: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Validate OIDC client credentials"""
        query = """
                SELECT * \
                FROM oidc_clients
                WHERE client_id = $1 \
                  AND is_active = TRUE \
                """

        client = await db.fetchrow(query, client_id)

        if not client:
            return None

        if client_secret:
            stored_secret = client['client_secret']
            if not bcrypt.checkpw(client_secret.encode('utf-8'), stored_secret.encode('utf-8')):
                return None

        return dict(client)

    @staticmethod
    async def validate_redirect_uri(
            db: asyncpg.Connection,
            client_id: str,
            redirect_uri: str
    ) -> bool:
        """Validate redirect URI for client"""
        query = """
                SELECT redirect_uris \
                FROM oidc_clients
                WHERE client_id = $1 \
                  AND is_active = TRUE \
                """
        result = await db.fetchval(query, client_id)

        if not result:
            return False

        return redirect_uri in result

    @staticmethod
    def generate_authorization_code() -> str:
        """Generate a secure authorization code"""
        return secrets.token_urlsafe(32)

    @staticmethod
    async def store_authorization_code(
            db: asyncpg.Connection,
            code: str,
            client_id: str,
            user_id: str,
            tenant_id: str,
            redirect_uri: str,
            scope: str,
            code_challenge: Optional[str] = None,
            code_challenge_method: Optional[str] = None,
            nonce: Optional[str] = None
    ):
        """Store authorization code with associated data"""
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

        await db.execute("""
                         INSERT INTO authorization_codes
                         (code, client_id, user_id, tenant_id, redirect_uri, scope,
                          code_challenge, code_challenge_method, nonce, expires_at)
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                         """, code, client_id, user_id, tenant_id, redirect_uri, scope,
                         code_challenge, code_challenge_method, nonce, expires_at)

    @staticmethod
    async def validate_authorization_code(
            db: asyncpg.Connection,
            code: str,
            client_id: str,
            redirect_uri: str,
            code_verifier: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Validate authorization code and return associated data"""
        query = """
                SELECT * \
                FROM authorization_codes
                WHERE code = $1 \
                  AND client_id = $2 \
                  AND redirect_uri = $3
                  AND used = FALSE \
                  AND expires_at > NOW() \
                """

        auth_code = await db.fetchrow(query, code, client_id, redirect_uri)

        if not auth_code:
            return None

        # Validate PKCE if present
        if auth_code['code_challenge']:
            if not code_verifier:
                return None

            if auth_code['code_challenge_method'] == 'S256':
                computed_challenge = base64.urlsafe_b64encode(
                    hashlib.sha256(code_verifier.encode()).digest()
                ).decode().rstrip('=')
            else:  # plain
                computed_challenge = code_verifier

            if computed_challenge != auth_code['code_challenge']:
                return None

        # Mark code as used
        await db.execute(
            "UPDATE authorization_codes SET used = TRUE WHERE code = $1",
            code
        )

        return dict(auth_code)

    @staticmethod
    async def create_id_token(
            user_id: str,
            email: str,
            tenant_id: str,
            client_id: str,
            nonce: Optional[str] = None,
            first_name: Optional[str] = None,
            last_name: Optional[str] = None,
            role: Optional[str] = None
    ) -> str:
        """Create an OpenID Connect ID token"""
        now = datetime.now(timezone.utc)

        payload = {
            "iss": "https://your-domain.com",  # Replace with actual issuer
            "sub": user_id,
            "aud": client_id,
            "exp": now + timedelta(hours=1),
            "iat": now,
            "email": email,
            "email_verified": True,
            "tenant_id": tenant_id,
        }

        if nonce:
            payload["nonce"] = nonce

        if first_name and last_name:
            payload["name"] = f"{first_name} {last_name}"
            payload["given_name"] = first_name
            payload["family_name"] = last_name

        if role:
            payload["role"] = role

        return await create_jwt_token(payload, JWT_SECRET)

    @staticmethod
    async def create_refresh_token(
            db: asyncpg.Connection,
            user_id: str,
            tenant_id: str,
            client_id: str,
            scope: str
    ) -> str:
        """Create and store a refresh token"""
        refresh_token = secrets.token_urlsafe(48)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=180)
        return refresh_token

    @staticmethod
    async def validate_refresh_token(
            db: asyncpg.Connection,
            refresh_token: str,
            client_id: str
    ) -> Optional[Dict[str, Any]]:
        """Validate refresh token and return associated data"""
        query = """
                SELECT * \
                FROM refresh_tokens
                WHERE token = $1 \
                  AND client_id = $2
                  AND revoked = FALSE \
                  AND expires_at > NOW() \
                """

        token_data = await db.fetchrow(query, refresh_token, client_id)

        if not token_data:
            return None

        return dict(token_data)

    @staticmethod
    async def revoke_refresh_token(
            db: asyncpg.Connection,
            refresh_token: str
    ):
        """Revoke a refresh token"""
        await db.execute(
            "UPDATE refresh_tokens SET revoked = TRUE WHERE token = $1",
            refresh_token
        )