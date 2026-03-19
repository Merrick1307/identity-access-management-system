"""
Create identity_providers table for brokered / federated login.

Depends on: 0001_create_tenants
"""
from yoyo import step

__depends__ = {"0001_create_tenants"}

steps = [
    step(
        """
        CREATE TABLE IF NOT EXISTS identity_providers (
            id VARCHAR(50) PRIMARY KEY,
            tenant_id VARCHAR(50) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            name VARCHAR(100) NOT NULL,
            protocol VARCHAR(20) NOT NULL DEFAULT 'oidc',
            issuer_url TEXT NOT NULL,
            client_id VARCHAR(255),
            client_secret TEXT,
            discovery_url TEXT,
            authorization_endpoint TEXT,
            token_endpoint TEXT,
            userinfo_endpoint TEXT,
            jwks_uri TEXT,
            jwt_validation_secret TEXT,
            enabled BOOLEAN DEFAULT TRUE,
            auto_link BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT NOW(),
            last_modified TIMESTAMP DEFAULT NOW(),
            UNIQUE (tenant_id, issuer_url),
            CONSTRAINT check_identity_provider_protocol CHECK (protocol IN ('oidc', 'saml'))
        )
        """,
        """
        DROP TABLE IF EXISTS identity_providers CASCADE
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_identity_providers_tenant
        ON identity_providers(tenant_id)
        """,
        """
        DROP INDEX IF EXISTS idx_identity_providers_tenant
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_identity_providers_enabled
        ON identity_providers(tenant_id) WHERE enabled = TRUE
        """,
        """
        DROP INDEX IF EXISTS idx_identity_providers_enabled
        """
    ),
]
