"""
Create users table.

Depends on: 0001_create_tenants
"""
from yoyo import step

__depends__ = {"0001_create_tenants"}

steps = [
    step(
        """
        CREATE TABLE IF NOT EXISTS users (
            id VARCHAR(50) PRIMARY KEY,
            tenant_id VARCHAR(50) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            email VARCHAR(255) NOT NULL,
            password VARCHAR(255) NOT NULL,
            first_name VARCHAR(100) NOT NULL,
            last_name VARCHAR(100) NOT NULL,
            role VARCHAR(100) DEFAULT NULL,
            is_active BOOLEAN DEFAULT TRUE,
            email_verified BOOLEAN DEFAULT FALSE,
            last_login TIMESTAMP DEFAULT NULL,
            created_at TIMESTAMP DEFAULT NOW(),
            last_modified TIMESTAMP DEFAULT NOW(),
            
            UNIQUE(tenant_id, email)
        )
        """,
        """
        DROP TABLE IF EXISTS users CASCADE
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS users_idx_email ON users(email)
        """,
        """
        DROP INDEX IF EXISTS users_idx_email
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS users_idx_tenants ON users(tenant_id)
        """,
        """
        DROP INDEX IF EXISTS users_idx_tenants
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS users_idx_email_tenants ON users(tenant_id, email)
        """,
        """
        DROP INDEX IF EXISTS users_idx_email_tenants
        """
    ),
]
