import asyncpg


class DBTables:
    def __init__(self, db: asyncpg.Connection):
        self.db = db

    user_table = """CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(120) PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255),
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    is_active BOOLEAN DEFAULT true,
    email_verified BOOLEAN DEFAULT false,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    last_modified TIMESTAMP DEFAULT NOW(),
    
    UNIQUE(tenant_id, email)
    )"""

    tenants_table = """CREATE TABLE IF NOT EXISTS tenants (
    id VARCHAR(120) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    domain VARCHAR(100) UNIQUE NOT NULL,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true
    )"""

    user_policies = """CREATE TABLE IF NOT EXISTS user_policies (
    tenant_id VARCHAR(50) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id VARCHAR(50) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(50),
    policies JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    last_modified TIMESTAMP DEFAULT NOW(),
        
    PRIMARY KEY (tenant_id, user_id)
    )"""

    tenants_idx_id = """CREATE INDEX IF NOT EXISTS tenants_idx_id ON tenants(id)"""
    tenants_idx_settings = """CREATE INDEX IF NOT EXISTS tenants_idx_settings ON tenants(GIN(settings)"""