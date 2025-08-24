import asyncpg
from fastapi import HTTPException, FastAPI, Request

from app.core.config import db_connection_string


class DBTables:
    def __init__(self, db: asyncpg.Connection):
        self.db = db

    user_table = """CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(120) PRIMARY KEY,
    tenant_id VARCHAR(120) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
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
    tenants_idx_settings = """CREATE INDEX IF NOT EXISTS tenants_idx_settings ON tenants USING GIN(settings)"""
    user_policies_idx = """CREATE INDEX IF NOT EXISTS user_policies_idx_id ON user_policies(tenant_id, user_id)"""
    users_idx_email = """CREATE INDEX IF NOT EXISTS users_idx_email ON users(email)"""
    users_idx_tenants = """CREATE INDEX IF NOT EXISTS users_idx_tenants ON users(tenant_id)"""
    users_idx_email_tenants = """CREATE INDEX IF NOT EXISTS users_idx_email_tenants ON users(tenant_id, email)"""


    tables = [user_table, tenants_table, user_policies]
    indexes = [user_policies_idx, tenants_idx_id, tenants_idx_settings]

    async def create_tables(self):
        try:
            for table in self.tables:
                table_created = await self.db.execute(table)
                if table_created != "CREATE TABLE":
                    raise HTTPException(status_code=400, detail="Table creation failed")

            for index in self.indexes:
                index_created = await self.db.execute(index)
                if index_created != "CREATE INDEX":
                    raise HTTPException(status_code=400, detail="Index creation failed")
        except asyncpg.exceptions as e:
            raise e
        except Exception:
            raise


async def lifespan(app: FastAPI):
    app.state.db_pool = asyncpg.create_pool(db_connection_string, min_size=15, max_size=200)

    async with app.state.db_pool.acquire() as connection:
        tables = DBTables(db=connection)
        await tables.create_tables()
    yield
    await app.state.db_pool.close()


async def get_database_pool(request: Request):
    async with request.app.state.db_pool.acquire() as connection:
        yield connection
