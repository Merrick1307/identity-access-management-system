"""
Create user_policies table.

Stores per-user policy assignments with JSONB policy data.
Depends on: 0002_create_users
"""
from yoyo import step

__depends__ = {"0002_create_users"}

steps = [
    step(
        """
        CREATE TABLE IF NOT EXISTS user_policies (
            tenant_id VARCHAR(50) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            user_id VARCHAR(50) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            policy_id VARCHAR(40),
            policy JSONB NOT NULL,
            created_at TIMESTAMP DEFAULT NOW(),
            last_modified TIMESTAMP DEFAULT NOW(),
            PRIMARY KEY (tenant_id, user_id, policy_id)
        )
        """,
        """
        DROP TABLE IF EXISTS user_policies CASCADE
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS user_policies_idx_id ON user_policies(tenant_id, user_id)
        """,
        """
        DROP INDEX IF EXISTS user_policies_idx_id
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_user_policies_user_tenant ON user_policies(user_id, tenant_id)
        """,
        """
        DROP INDEX IF EXISTS idx_user_policies_user_tenant
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_user_policies_policy_gin ON user_policies USING GIN (policy)
        """,
        """
        DROP INDEX IF EXISTS idx_user_policies_policy_gin
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_user_policies_department ON user_policies (
            tenant_id, ((policy -> 'condition' ->> 'department'))
        )
        """,
        """
        DROP INDEX IF EXISTS idx_user_policies_department
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_user_policies_resource ON user_policies (
            tenant_id, ((policy ->> 'resource'))
        )
        """,
        """
        DROP INDEX IF EXISTS idx_user_policies_resource
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_user_policies_validity ON user_policies (
            tenant_id, (policy -> 'condition' ->> 'validity_time')
        )
        """,
        """
        DROP INDEX IF EXISTS idx_user_policies_validity
        """
    ),
]
