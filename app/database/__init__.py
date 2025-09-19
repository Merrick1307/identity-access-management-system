import asyncpg
from fastapi import HTTPException, FastAPI, Request, status
from rbloom import Bloom

from app.core.config import db_connection_string


class DBTables:
    def __init__(self, db: asyncpg.Connection):
        self.db = db

    user_table = """CREATE TABLE IF NOT EXISTS users (
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
    )"""

    tenants_table = """CREATE TABLE IF NOT EXISTS tenants (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    domain VARCHAR(100) UNIQUE NOT NULL,
    root VARCHAR(255) NOT NULL,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE
    )"""

    user_policies = """CREATE TABLE IF NOT EXISTS user_policies (
    tenant_id VARCHAR(50) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id VARCHAR(50) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    policy_id VARCHAR(40),
    policy JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    last_modified TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (tenant_id, user_id, policy_id)
    )"""

    policies = """CREATE TABLE IF NOT EXISTS tenant_policies (
                id VARCHAR(50) PRIMARY KEY,
                tenant_id VARCHAR(50) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                policies JSONB NOT NULL,
                roles TEXT[] DEFAULT '{}',
                created_at TIMESTAMP DEFAULT NOW(),
                last_modified TIMESTAMP DEFAULT NOW()
                )"""

    audit_logs = """CREATE TABLE IF NOT EXISTS audit_logs \
                    ( \
                        id          SERIAL PRIMARY KEY, \
                        timestamp   TIMESTAMP WITH TIME ZONE NOT NULL, \
                        level       VARCHAR(20)              NOT NULL, \
                        logger_name VARCHAR(100)             NOT NULL, \
                        message     TEXT                     NOT NULL, \
                        module      VARCHAR(100), \
                        function    VARCHAR(100), \
                        line_number INTEGER, \
                        thread_id   BIGINT, \
                        process_id  INTEGER, \
                        extra_data  JSONB, \
                        created_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                    ) \
                 """

    tenants_idx_id = """CREATE INDEX IF NOT EXISTS tenants_idx_id ON tenants(id)"""
    tenants_idx_settings = """CREATE INDEX IF NOT EXISTS tenants_idx_settings ON tenants USING GIN(settings)"""
    user_policies_idx = """CREATE INDEX IF NOT EXISTS user_policies_idx_id ON user_policies(tenant_id, user_id)"""
    users_idx_email = """CREATE INDEX IF NOT EXISTS users_idx_email ON users(email)"""
    users_idx_tenants = """CREATE INDEX IF NOT EXISTS users_idx_tenants ON users(tenant_id)"""
    users_idx_email_tenants = """CREATE INDEX IF NOT EXISTS users_idx_email_tenants ON users(tenant_id, email)"""
    user_policies_policy_gin_idx = """CREATE INDEX IF NOT EXISTS idx_user_policies_policy_gin ON user_policies USING GIN (policy)"""
    user_policies_department_idx = """
    CREATE INDEX IF NOT EXISTS idx_user_policies_department ON user_policies (
    tenant_id, ((policy -> 'condition' ->> 'department'))
    )"""
    user_policies_resource_idx = """
    CREATE INDEX IF NOT EXISTS idx_user_policies_resource ON user_policies (
    tenant_id, ((policy ->> 'resource'))
    )"""
    user_policies_validity_idx = """
    CREATE INDEX IF NOT EXISTS idx_user_policies_validity ON user_policies (
    tenant_id, (policy -> 'condition' ->> 'validity_time')
    )"""
    audit_logs_idx_timestamp = """CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs (timestamp)"""
    audit_logs_idx_level = """CREATE INDEX IF NOT EXISTS idx_audit_logs_level ON audit_logs (level)"""
    audit_logs_idx_name = """CREATE INDEX IF NOT EXISTS idx_audit_logs_logger_name ON audit_logs (logger_name)"""


    tables = [tenants_table, user_table, user_policies, audit_logs]
    indexes = [
        user_policies_idx, tenants_idx_id, tenants_idx_settings, users_idx_email,
        user_policies_validity_idx, user_policies_department_idx, user_policies_resource_idx,
        user_policies_policy_gin_idx, users_idx_tenants, users_idx_email_tenants,
        audit_logs_idx_timestamp, audit_logs_idx_level, audit_logs_idx_name,
    ]

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
        except asyncpg.exceptions.PostgresError as e:
            raise e
        except Exception:
            raise


async def lifespan(app: FastAPI):
    app.state.db_pool = await asyncpg.create_pool(db_connection_string, min_size=15, max_size=200)
    app.state.bloom_filter = Bloom(expected_items=10000000, false_positive_rate=0.0001)

    async with app.state.db_pool.acquire() as connection:
        tables = DBTables(db=connection)
        await tables.create_tables()
    yield
    await app.state.db_pool.close()


async def get_database_pool(request: Request):
    async with request.app.state.db_pool.acquire() as connection:
        yield connection

async def get_bloom(request: Request):
    return request.app.state.bloom_filter
