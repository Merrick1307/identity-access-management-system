"""
Create federated identity links between external broker identities and tenant-local users.

Depends on: 0018_create_identity_providers, 0002_create_users
"""
from yoyo import step

__depends__ = {"0018_create_identity_providers", "0002_create_users"}

steps = [
    step(
        """
        CREATE TABLE IF NOT EXISTS federated_identities (
            id VARCHAR(50) PRIMARY KEY,
            tenant_id VARCHAR(50) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            provider_id VARCHAR(50) NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
            user_id VARCHAR(50) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            external_subject TEXT NOT NULL,
            external_email TEXT,
            created_at TIMESTAMP DEFAULT NOW(),
            UNIQUE (tenant_id, provider_id, external_subject),
            UNIQUE (tenant_id, provider_id, user_id)
        )
        """,
        """
        DROP TABLE IF EXISTS federated_identities CASCADE
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_federated_identities_user
        ON federated_identities(tenant_id, user_id)
        """,
        """
        DROP INDEX IF EXISTS idx_federated_identities_user
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_federated_identities_provider_subject
        ON federated_identities(tenant_id, provider_id, external_subject)
        """,
        """
        DROP INDEX IF EXISTS idx_federated_identities_provider_subject
        """
    ),
]
