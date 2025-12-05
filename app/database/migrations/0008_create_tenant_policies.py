"""
Create tenant_policies table.

Stores tenant-level policy templates and role definitions.
Depends on: 0001_create_tenants
"""
from yoyo import step

__depends__ = {"0001_create_tenants"}

steps = [
    step(
        """
        CREATE TABLE IF NOT EXISTS tenant_policies (
            id VARCHAR(50) PRIMARY KEY,
            tenant_id VARCHAR(50) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            policies JSONB NOT NULL,
            roles TEXT[] DEFAULT '{}',
            created_at TIMESTAMP DEFAULT NOW(),
            last_modified TIMESTAMP DEFAULT NOW()
        )
        """,
        """
        DROP TABLE IF EXISTS tenant_policies CASCADE
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_tenant_policies_tenant 
        ON tenant_policies(tenant_id)
        """,
        """
        DROP INDEX IF EXISTS idx_tenant_policies_tenant
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_tenant_policies_gin 
        ON tenant_policies USING GIN(policies)
        """,
        """
        DROP INDEX IF EXISTS idx_tenant_policies_gin
        """
    ),
]
