from yoyo import step

__depends__ = {"0001_create_tenants"}

steps = [
    step(
        """
        CREATE TABLE IF NOT EXISTS oidc_clients (
            id VARCHAR(50) PRIMARY KEY,
            tenant_id VARCHAR(50) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            client_secret VARCHAR(255) NOT NULL,
            name VARCHAR(100) NOT NULL,
            redirect_uris TEXT[] NOT NULL,
            scopes TEXT[] DEFAULT '{}',
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT NOW(),
            last_modified TIMESTAMP DEFAULT NOW()
        )
        """,
        """
        DROP TABLE IF EXISTS oidc_clients CASCADE
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_oidc_clients_tenant 
        ON oidc_clients(tenant_id)
        """,
        """
        DROP INDEX IF EXISTS idx_oidc_clients_tenant
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_oidc_clients_active 
        ON oidc_clients(tenant_id) WHERE is_active = TRUE
        """,
        """
        DROP INDEX IF EXISTS idx_oidc_clients_active
        """
    ),
]
