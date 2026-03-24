"""
Pytest configuration and shared fixtures for HEX IAM tests.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import asyncio
import os
from datetime import datetime, timezone, timedelta
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("DATABASE_URL", "localhost:5432/test_db")
os.environ.setdefault("DATABASE_USER", "test_user")
os.environ.setdefault("DATABASE_PASSWORD", "test_password")
os.environ.setdefault("JWT_SECRET", "test-secret-key-for-jwt-signing-min-32-chars")
os.environ.setdefault("OTP_SECRET", "test-otp-secret")
os.environ.setdefault("ALGORITHM", "HS256")
os.environ.setdefault("MAIL_USERNAME", "test@test.com")
os.environ.setdefault("MAIL_PASSWORD", "test_password")
os.environ.setdefault("MAIL_FROM", "noreply@test.com")
os.environ.setdefault("MAIL_PORT", "587")
os.environ.setdefault("MAIL_SERVER", "smtp.test.com")
os.environ.setdefault("MAIL_SSL_TLS", "0")
os.environ.setdefault("MAIL_STARTTLS", "1")


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_db_connection():
    """Mock asyncpg connection."""
    mock_conn = AsyncMock()
    mock_conn.fetch = AsyncMock(return_value=[])
    mock_conn.fetchrow = AsyncMock(return_value=None)
    mock_conn.fetchval = AsyncMock(return_value=None)
    mock_conn.execute = AsyncMock(return_value="UPDATE 1")
    mock_conn.executemany = AsyncMock()
    mock_conn.transaction = MagicMock()
    mock_conn.transaction.return_value.__aenter__ = AsyncMock()
    mock_conn.transaction.return_value.__aexit__ = AsyncMock()
    return mock_conn


@pytest.fixture
def mock_redis():
    """Mock Redis client."""
    mock = AsyncMock()
    mock.xadd = AsyncMock()
    mock.xrange = AsyncMock(return_value=[])
    mock.xreadgroup = AsyncMock(return_value=[])
    mock.xack = AsyncMock()
    mock.xgroup_create = AsyncMock()
    mock.xinfo_stream = AsyncMock(return_value={"length": 0})
    mock.pubsub_numsub = AsyncMock(return_value=[(b"hexiam:revocations", 0)])
    pubsub = AsyncMock()
    pubsub.subscribe = AsyncMock()
    pubsub.unsubscribe = AsyncMock()
    pubsub.close = AsyncMock()
    pubsub.get_message = AsyncMock(return_value=None)
    mock.pubsub = MagicMock(return_value=pubsub)
    mock.publish = AsyncMock(return_value=1)
    mock.pipeline = MagicMock()
    mock.pipeline.return_value.execute = AsyncMock()
    return mock


@pytest.fixture
def mock_bloom_filter():
    """Mock Bloom filter."""
    mock = MagicMock()
    mock.add = MagicMock()
    mock.__contains__ = MagicMock(return_value=False)
    return mock


@pytest.fixture
def mock_audit_logger():
    """Mock AuditLogger."""
    mock = MagicMock()
    mock.info = MagicMock()
    mock.warning = MagicMock()
    mock.error = MagicMock()
    mock.debug = MagicMock()
    mock.audit = MagicMock()
    mock.force_info = AsyncMock()
    mock.force_warning = AsyncMock()
    mock.force_error = AsyncMock()
    mock.log_exception = AsyncMock()
    return mock


@pytest.fixture
def mock_revocation_manager(mock_redis, mock_bloom_filter):
    """Mock TokenRevocationManager."""
    from app.core.token_revocation import TokenRevocationManager
    
    manager = MagicMock(spec=TokenRevocationManager)
    manager.redis = mock_redis
    manager.bloom = mock_bloom_filter
    manager.revoke_token = AsyncMock(return_value=True)
    manager.revoke_user_tokens = AsyncMock(return_value=1)
    manager.is_revoked = MagicMock(return_value=False)
    return manager


@pytest.fixture
def sample_user_data():
    """Sample user data for tests."""
    return {
        "id": "user-123-uuid",
        "email": "test@example.com",
        "password": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.G2vQHqBcbJyJSq",  # "password123"
        "first_name": "Test",
        "last_name": "User",
        "role": "admin",
        "tenant_id": "tenant-456-uuid",
        "is_active": True,
        "email_verified": True
    }


@pytest.fixture
def sample_tenant_data():
    """Sample tenant data for tests."""
    return {
        "id": "tenant-456-uuid",
        "name": "Test Corp",
        "domain": "testcorp.com",
        "root": "admin@testcorp.com",
        "is_active": True,
        "settings": {
            "mfa": {"enabled": False},
            "tokens": {"access_token_ttl": 3600}
        }
    }


@pytest.fixture
def sample_policy_data():
    """Sample policy data for tests."""
    return {
        "policy_id": "admin_policy",
        "resource": "users",
        "actions": ["read", "write", "delete"],
        "conditions": {"department": "engineering"}
    }


@pytest.fixture
def valid_jwt_token(sample_user_data):
    """Generate a valid JWT token for testing."""
    import jwt
    from app.core.config import JWT_SECRET
    
    payload = {
        "sub": sample_user_data["email"],
        "user_id": sample_user_data["id"],
        "tenant_id": sample_user_data["tenant_id"],
        "role": sample_user_data["role"],
        "policy": {"users": 7, "documents": 3},
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        "iat": datetime.now(timezone.utc)
    }
    headers = {"jti": f"{sample_user_data['id']}-{int(datetime.now().timestamp() * 1000)}"}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256", headers=headers)


@pytest.fixture
def expired_jwt_token(sample_user_data):
    """Generate an expired JWT token for testing."""
    import jwt
    from app.core.config import JWT_SECRET
    
    payload = {
        "sub": sample_user_data["email"],
        "user_id": sample_user_data["id"],
        "tenant_id": sample_user_data["tenant_id"],
        "role": sample_user_data["role"],
        "policy": {},
        "exp": datetime.now(timezone.utc) - timedelta(hours=1),
        "iat": datetime.now(timezone.utc) - timedelta(hours=2)
    }
    headers = {"jti": f"{sample_user_data['id']}-expired"}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256", headers=headers)


@pytest.fixture
def mock_app_state(mock_db_connection, mock_redis, mock_bloom_filter, mock_revocation_manager):
    """Mock FastAPI app state."""
    state = MagicMock()
    state.dbconnection = MagicMock()
    state.dbconnection.acquire = MagicMock()
    state.dbconnection.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_db_connection)
    state.dbconnection.acquire.return_value.__aexit__ = AsyncMock()
    state.redis = mock_redis
    state.bloom_filter = mock_bloom_filter
    state.revocation_manager = mock_revocation_manager
    return state
