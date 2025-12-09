"""
Authorization Codes table.

Stores OAuth2/OIDC authorization codes for the authorization code grant flow.
Supports PKCE (code_challenge/code_challenge_method) and OIDC nonce.
Depends on: 0009_create_oidc_clients, 0002_create_users
"""
from yoyo import step

__depends__ = {"0009_create_oidc_clients", "0002_create_users"}

steps = [
    step(
        """
        CREATE TABLE IF NOT EXISTS authorization_codes (
            id VARCHAR(50) PRIMARY KEY,
            code VARCHAR(255) NOT NULL UNIQUE,
            client_id VARCHAR(50) NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
            user_id VARCHAR(50) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            tenant_id VARCHAR(50) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            redirect_uri TEXT NOT NULL,
            scope TEXT NOT NULL,
            state VARCHAR(255),
            code_challenge VARCHAR(255),
            code_challenge_method VARCHAR(10),
            nonce VARCHAR(255),
            used BOOLEAN DEFAULT FALSE,
            expires_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            ip_address VARCHAR(45),
            user_agent TEXT
        )
        """,
        """
        DROP TABLE IF EXISTS authorization_codes CASCADE
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_authorization_codes_code 
        ON authorization_codes(code) WHERE used = FALSE
        """,
        """
        DROP INDEX IF EXISTS idx_authorization_codes_code
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_authorization_codes_client 
        ON authorization_codes(client_id)
        """,
        """
        DROP INDEX IF EXISTS idx_authorization_codes_client
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires 
        ON authorization_codes(expires_at) WHERE used = FALSE
        """,
        """
        DROP INDEX IF EXISTS idx_authorization_codes_expires
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_authorization_codes_user 
        ON authorization_codes(user_id, tenant_id)
        """,
        """
        DROP INDEX IF EXISTS idx_authorization_codes_user
        """
    ),
]
