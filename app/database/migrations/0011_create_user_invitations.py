"""
User Invitations table.

Stores invitations for invite-only user signup.
Depends on: 0001_create_tenants, 0009_create_oidc_clients
"""
from yoyo import step

__depends__ = {"0001_create_tenants", "0009_create_oidc_clients"}

steps = [
    step(
        """
        CREATE TABLE IF NOT EXISTS user_invitations (
            id VARCHAR(50) PRIMARY KEY,
            tenant_id VARCHAR(50) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            client_id VARCHAR(50) REFERENCES oidc_clients(id) ON DELETE SET NULL,
            email VARCHAR(255) NOT NULL,
            role VARCHAR(100),
            invited_by VARCHAR(50),
            expires_at TIMESTAMPTZ NOT NULL,
            accepted_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            
            UNIQUE(tenant_id, email)
        )
        """,
        """
        DROP TABLE IF EXISTS user_invitations CASCADE
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_user_invitations_email 
        ON user_invitations(tenant_id, email)
        """,
        """
        DROP INDEX IF EXISTS idx_user_invitations_email
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_user_invitations_expires 
        ON user_invitations(expires_at) WHERE accepted_at IS NULL
        """,
        """
        DROP INDEX IF EXISTS idx_user_invitations_expires
        """
    ),
]
