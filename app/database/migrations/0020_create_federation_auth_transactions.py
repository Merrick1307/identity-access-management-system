"""
Create federation_auth_transactions for upstream browser federation handoff.

Depends on: 0018_create_identity_providers, 0009_create_oidc_clients
"""
from yoyo import step

__depends__ = {"0018_create_identity_providers", "0009_create_oidc_clients"}

steps = [
    step(
        """
        CREATE TABLE IF NOT EXISTS federation_auth_transactions (
            id VARCHAR(50) PRIMARY KEY,
            tenant_id VARCHAR(50) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            provider_id VARCHAR(50) NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
            client_id VARCHAR(255) NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
            redirect_uri TEXT NOT NULL,
            scope TEXT NOT NULL,
            state TEXT,
            nonce TEXT,
            code_challenge TEXT,
            code_challenge_method TEXT,
            upstream_state TEXT NOT NULL,
            upstream_nonce TEXT,
            created_at TIMESTAMP DEFAULT NOW(),
            expires_at TIMESTAMP NOT NULL,
            consumed_at TIMESTAMP,
            UNIQUE (provider_id, upstream_state)
        )
        """,
        """
        DROP TABLE IF EXISTS federation_auth_transactions CASCADE
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_federation_auth_transactions_lookup
        ON federation_auth_transactions(provider_id, upstream_state)
        WHERE consumed_at IS NULL
        """,
        """
        DROP INDEX IF EXISTS idx_federation_auth_transactions_lookup
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_federation_auth_transactions_expiry
        ON federation_auth_transactions(expires_at)
        """,
        """
        DROP INDEX IF EXISTS idx_federation_auth_transactions_expiry
        """
    ),
]
