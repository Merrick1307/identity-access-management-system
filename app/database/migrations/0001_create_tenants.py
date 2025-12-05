"""
Create tenants table.

This is the foundational table - all other tables reference tenants.
"""
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
]
