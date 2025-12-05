"""
Create user_sessions table.

Tracks active user sessions for session management and revocation.
Depends on: 0002_create_users
"""
from yoyo import step

__depends__ = {"0002_create_users"}

steps = [
    step(
        """
        CREATE TABLE IF NOT EXISTS user_sessions (
            jti VARCHAR(64) PRIMARY KEY,
            user_id VARCHAR(50) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            tenant_id VARCHAR(50) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            device_info JSONB,
            ip_address INET,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            expires_at TIMESTAMPTZ NOT NULL,
            revoked_at TIMESTAMPTZ,
            revoked_reason VARCHAR(50)
        )
        """,
        """
        DROP TABLE IF EXISTS user_sessions CASCADE
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_sessions_user_active 
        ON user_sessions(user_id, tenant_id) WHERE revoked_at IS NULL
        """,
        """
        DROP INDEX IF EXISTS idx_sessions_user_active
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_sessions_expires 
        ON user_sessions(expires_at) WHERE revoked_at IS NULL
        """,
        """
        DROP INDEX IF EXISTS idx_sessions_expires
        """
    ),
]
