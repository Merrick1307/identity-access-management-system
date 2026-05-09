"""
Database module for HEX IAM.

Provides:
- Connection pool management
- Migration runner integration
- Redis client for audit logs
- Bloom filter for token revocation
"""
import asyncio
from contextlib import asynccontextmanager
import logging
import os
from pathlib import Path
from typing import Optional

import asyncpg
import redis.asyncio as redis
from fastapi import HTTPException, FastAPI, Request
from rbloom import Bloom
from yoyo import read_migrations, get_backend

from app.audit_logs import init_audit_logger, shutdown_audit_logger
from app.core.config import db_connection_string, db_owner_connection_string
from app.core.token_revocation import init_revocation_manager, shutdown_revocation_manager
from app.services.federation_service import init_network_clients, shutdown_network_clients

logger = logging.getLogger(__name__)

REDIS_USER = os.getenv("REDIS_USER", "default")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")
REDIS_DB: str = os.getenv("REDIS_DB", "0")
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
    
    pending = backend.to_apply(migrations)
    applied = backend.to_rollback(migrations)
    
    pending_list = list(pending)
    applied_list = list(applied)
    
    result = {
        "pending_count": len(pending_list),
        "applied_count": len(applied_list),
        "pending": [m.id for m in pending_list],
        "newly_applied": []
    }
    
    if pending_list and auto_apply:
        logger.info(f"Applying {len(pending_list)} pending migration(s)...")
        for migration in pending_list:
            logger.info(f"  → {migration.id}")
        
        try:
            backend.apply_migrations(backend.to_apply(migrations))
            result["newly_applied"] = [m.id for m in pending_list]
            logger.info("✓ Migrations applied successfully")
        except Exception as e:
            if "duplicate key" in str(e) or "UniqueViolation" in str(type(e).__name__):
                logger.info("✓ Migrations already applied by another worker")
            else:
                raise
    elif pending_list:
        logger.warning(f"{len(pending_list)} pending migrations not applied (auto_apply=False)")
    else:
        logger.info("✓ Database schema is up to date")
    
    backend.connection.close()
    return result


EMBEDDED_AUDIT_CONSUMER = os.getenv("EMBEDDED_AUDIT_CONSUMER", "true").lower() == "true"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan manager for database and services initialization."""
    
    logger.info("Running database migrations...")
    try:
        migration_result = run_migrations(db_connection_string, auto_apply=True)
        if migration_result["newly_applied"]:
            logger.info(f"Applied migrations: {migration_result['newly_applied']}")
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        raise
    
    app.state.db_pool = await asyncpg.create_pool(
        db_connection_string,
        min_size=3, max_size=8,
        max_queries=100000,
        max_inactive_connection_lifetime=600,
        command_timeout=30,
        server_settings={
            "jit_above_cost": "200000",
            "jit_inline_above_cost": "500000"
        }
    )
    app.state.db_owner_pool = await asyncpg.create_pool(
        db_owner_connection_string,
        min_size=2, max_size=5,
        max_queries=100000,
        max_inactive_connection_lifetime=200,
        command_timeout=20,
        server_settings={
            "jit_above_cost": "20000",
            "jit_inline_above_cost": "50000"
        }
    )
    if REDIS_USER and REDIS_PASSWORD:
        REDIS_URL = f"redis://{REDIS_USER}:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"
    elif REDIS_PASSWORD:
        REDIS_URL = f"redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"
    else:
        REDIS_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"
    
    app.state.redis = redis.from_url(
        REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
        max_connections=20
    )
    
    app.state.bloom_filter = Bloom(expected_items=10000000, false_positive_rate=0.0001)
    
    await init_network_clients()
    await init_audit_logger(app.state)
    await init_revocation_manager(app.state)
    
    audit_consumer_task = None
    if EMBEDDED_AUDIT_CONSUMER:
        from app.audit_logs.consumer import AuditLogConsumer
        app.state.audit_consumer = AuditLogConsumer()
        await app.state.audit_consumer.connect()
        audit_consumer_task = asyncio.create_task(app.state.audit_consumer.run())
        logger.info("Embedded audit log consumer started")
    
    logger.info("HEX IAM startup complete")
    
    yield
    
    logger.info("Shutting down HEX IAM...")
    
    if EMBEDDED_AUDIT_CONSUMER and hasattr(app.state, 'audit_consumer'):
        app.state.audit_consumer.stop()
        if audit_consumer_task:
            audit_consumer_task.cancel()
            try:
                await audit_consumer_task
            except asyncio.CancelledError:
                pass
        await app.state.audit_consumer.close()
        logger.info("Audit consumer stopped")
    
    await shutdown_revocation_manager()
    await shutdown_audit_logger()
    await shutdown_network_clients()
    await app.state.redis.close()
    await app.state.db_pool.close()
    await app.state.db_owner_pool.close()
    
    logger.info("HEX IAM shutdown complete")


async def get_database_pool(request: Request):
    """Database connection with tenant context from X-TENANT-ID header."""
    tenant_id = request.headers.get("X-TENANT-ID", None)
    if not tenant_id:
        client_id = request.query_params.get("client_id")
        if not client_id:
            form_data = await request.form()
            client_id = form_data.get("client_id")

        if client_id:
            # Look up tenant_id from client_id
            async with request.app.state.db_pool.acquire() as temp_conn:
                tenant_id = await temp_conn.fetchval(
                    "SELECT tenant_id FROM oidc_clients WHERE id = $1",
                    client_id
                )

    if not tenant_id:
        raise HTTPException(400, "Tenant ID or valid client_id required")
    
    async with request.app.state.db_pool.acquire() as connection:
        await connection.execute("SELECT set_config('app.tenant_id', $1, false)", tenant_id)
        yield connection
        await connection.execute("SELECT set_config('app.tenant_id', '', false)")


async def get_database_pool_no_tenant(request: Request):
    """Database connection without tenant context - for public endpoints like onboarding."""
    async with request.app.state.db_owner_pool.acquire() as connection:
        yield connection


# def validate_tenant_context(jwt_tenant_id: str, header_tenant_id: str):
#     """
#     Validate that JWT tenant matches header tenant.
#     Calls this in routes after JWT verification to prevent tenant spoofing.
#     """
#     if jwt_tenant_id != header_tenant_id:
#         raise HTTPException(
#             status_code=403,
#             detail="Tenant context mismatch - access denied"
#         )

async def get_bloom(request: Request):
    return request.app.state.bloom_filter


async def get_revocation_manager(request: Request):
    """Dependency to get the token revocation manager."""
    return request.app.state.revocation_manager
