"""
Create refresh_tokens table.

Stores refresh token JTIs for token rotation and revocation.
Depends on: 0002_create_users
"""
from yoyo import step

__depends__ = {"0002_create_users"}

steps = [
    step(
        """
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            jti VARCHAR(255) PRIMARY KEY,
            user_id VARCHAR(50) NOT NULL,
            tenant_id VARCHAR(50) NOT NULL,
            client_id VARCHAR(100) NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            revoked BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT NOW()
        )
        """,
        """
        DROP TABLE IF EXISTS refresh_tokens CASCADE
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_revocation 
        ON refresh_tokens(user_id, tenant_id)
        """,
        """
        DROP INDEX IF EXISTS idx_refresh_tokens_user_revocation
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires 
        ON refresh_tokens(expires_at) WHERE revoked = FALSE
        """,
        """
        DROP INDEX IF EXISTS idx_refresh_tokens_expires
        """
    ),
]
