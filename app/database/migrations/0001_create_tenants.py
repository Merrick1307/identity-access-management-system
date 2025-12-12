from yoyo import step

steps = [
    step(
        """
        CREATE TABLE IF NOT EXISTS tenants (
            id VARCHAR(50) PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            domain VARCHAR(100) UNIQUE NOT NULL,
            root VARCHAR(255) NOT NULL,
            settings JSONB DEFAULT '{}',
            created_at TIMESTAMP DEFAULT NOW(),
            is_active BOOLEAN DEFAULT TRUE
        )
        """,
        """
        DROP TABLE IF EXISTS tenants CASCADE
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS tenants_idx_id ON tenants(id)
        """,
        """
        DROP INDEX IF EXISTS tenants_idx_id
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS tenants_idx_settings ON tenants USING GIN(settings)
        """,
        """
        DROP INDEX IF EXISTS tenants_idx_settings
        """
    ),
    step(
        """
        ALTER TABLE tenants 
        ADD CONSTRAINT check_mfa_settings 
        CHECK (
            settings IS NULL OR 
            jsonb_typeof(settings->'mfa_enabled') IN ('boolean', 'null')
        );
        """,
        """
        ALTER TABLE tenants 
        DROP CONSTRAINT check_mfa_settings;
        """
    )
]
