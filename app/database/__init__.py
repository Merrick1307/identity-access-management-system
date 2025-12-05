"""
Database module for HEX IAM.

Provides:
- Connection pool management
- Migration runner integration
- Redis client for audit logs
- Bloom filter for token revocation
"""
from contextlib import asynccontextmanager
import logging
import os
from pathlib import Path

import asyncpg
import redis.asyncio as redis
from fastapi import HTTPException, FastAPI, Request
from rbloom import Bloom
from yoyo import read_migrations, get_backend

from app.audit_logs import init_audit_logger, shutdown_audit_logger
from app.core.config import db_connection_string

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
MIGRATIONS_PATH = Path(__file__).parent / "migrations"


def run_migrations(database_url: str, auto_apply: bool = True) -> dict:
    """
    Run database migrations using yoyo.
    
    Args:
        database_url: PostgreSQL connection string
        auto_apply: If True, automatically apply pending migrations
        
    Returns:
        dict with migration status
    """
    backend = get_backend(database_url)
    migrations = read_migrations(str(MIGRATIONS_PATH))
    
    pending = list(backend.to_apply(migrations))
    applied = list(backend.to_rollback(migrations))
    
    result = {
        "pending_count": len(pending),
        "applied_count": len(applied),
        "pending": [m.id for m in pending],
        "newly_applied": []
    }
    
    if pending and auto_apply:
        logger.info(f"Applying {len(pending)} pending migration(s)...")
        for migration in pending:
            logger.info(f"  → {migration.id}")
        
        backend.apply_migrations(pending)
        result["newly_applied"] = [m.id for m in pending]
        logger.info("✓ Migrations applied successfully")
    elif pending:
        logger.warning(f"{len(pending)} pending migrations not applied (auto_apply=False)")
    else:
        logger.info("✓ Database schema is up to date")
    
    backend.connection.close()
    return result


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan manager for database and services initialization."""
    
    # Run migrations before starting the app
    logger.info("Running database migrations...")
    try:
        migration_result = run_migrations(db_connection_string, auto_apply=True)
        if migration_result["newly_applied"]:
            logger.info(f"Applied migrations: {migration_result['newly_applied']}")
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        raise
    
    # Create connection pool
    app.state.db_pool = await asyncpg.create_pool(
        db_connection_string,
        min_size=15, max_size=30,
        max_queries=100000,
        max_inactive_connection_lifetime=600,
        command_timeout=30,
        server_settings={
            "jit_above_cost": "200000",
            "jit_inline_above_cost": "500000"
        }
    )
    
    # Redis client for audit logs
    app.state.redis = redis.from_url(
        REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
        max_connections=20
    )
    
    # Bloom filter for token revocation
    app.state.bloom_filter = Bloom(expected_items=10000000, false_positive_rate=0.0001)
    
    # Initialize audit logger (starts background flush loop)
    await init_audit_logger(app.state)
    
    logger.info("HEX IAM startup complete")
    
    yield
    
    # Shutdown sequence
    logger.info("Shutting down HEX IAM...")
    
    # Flush remaining logs and stop logger
    await shutdown_audit_logger()
    
    # Close Redis
    await app.state.redis.close()
    
    # Close PostgreSQL pool
    await app.state.db_pool.close()
    
    logger.info("HEX IAM shutdown complete")


async def get_database_pool(request: Request):
    async with request.app.state.db_pool.acquire() as connection:
        tenant_id = request.headers.get("X-TENANT-ID")
        if not tenant_id:
            raise HTTPException(400, "Tenant ID required")

        # RLS context set locally (resets on release)
        await connection.execute("SELECT set_config('app.tenant_id', $1, true)", tenant_id)
        yield connection

async def get_bloom(request: Request):
    return request.app.state.bloom_filter
