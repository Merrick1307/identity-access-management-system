"""
Tests for app/audit_logs/redis_logger.py - Redis Streams audit logging.
"""
import pytest
import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from app.audit_logs.redis_logger import (
    RedisLogBuffer,
    AuditLogger,
    get_audit_logger,
    init_audit_logger,
    shutdown_audit_logger,
    background_logger,
    AuditLoggingMiddleware,
    STREAM_NAME,
    MAX_STREAM_LEN
)


class TestRedisLogBuffer:
    """Tests for RedisLogBuffer class."""
    
    @pytest.fixture
    def log_buffer(self, mock_redis):
        """Create a RedisLogBuffer instance."""
        return RedisLogBuffer(
            redis_client=mock_redis,
            stream_name=STREAM_NAME,
            buffer_size=5,
            flush_interval=0.1
        )
    
    @pytest.mark.asyncio
    async def test_publish_adds_to_buffer(self, log_buffer):
        """Test that publish adds log to buffer."""
        log_entry = {"level": "INFO", "message": "Test log"}
        
        await log_buffer.publish(log_entry)
        
        assert len(log_buffer._buffer) == 1
    
    @pytest.mark.asyncio
    async def test_publish_multiple_logs(self, log_buffer, mock_redis):
        """Test publishing multiple logs to buffer."""
        for i in range(3):
            await log_buffer.publish({"level": "INFO", "message": f"Log {i}"})
        
        assert len(log_buffer._buffer) == 3
    
    @pytest.mark.asyncio
    async def test_publish_immediate(self, log_buffer, mock_redis):
        """Test immediate publish bypasses buffer."""
        mock_redis.xadd = AsyncMock()
        
        await log_buffer.publish_immediate({"level": "ERROR", "message": "Critical"})
        
        mock_redis.xadd.assert_called_once()
        assert len(log_buffer._buffer) == 0
    
    @pytest.mark.asyncio
    async def test_start_creates_flush_task(self, log_buffer):
        """Test that start creates background flush task."""
        await log_buffer.start()
        
        assert log_buffer._running is True
        assert log_buffer._flush_task is not None
        
        await log_buffer.stop()
    
    @pytest.mark.asyncio
    async def test_stop_flushes_remaining(self, log_buffer, mock_redis):
        """Test that stop flushes remaining buffer."""
        mock_redis.pipeline.return_value.execute = AsyncMock()
        
        await log_buffer.publish({"level": "INFO", "message": "Test"})
        await log_buffer.stop()
        
        assert log_buffer._running is False


class TestAuditLogger:
    """Tests for AuditLogger class."""
    
    def test_singleton_pattern(self, mock_redis):
        """Test that AuditLogger follows singleton pattern."""
        AuditLogger._instance = None
        
        app_state = MagicMock()
        app_state.redis = mock_redis
        
        logger1 = AuditLogger.get_instance(app_state)
        logger2 = AuditLogger.get_instance()
        
        assert logger1 is logger2
        
        AuditLogger._instance = None
    
    @pytest.mark.asyncio
    async def test_force_info_immediate(self, mock_redis):
        """Test that force_info publishes immediately."""
        AuditLogger._instance = None
        app_state = MagicMock()
        app_state.redis = mock_redis
        mock_redis.xadd = AsyncMock()
        
        logger = AuditLogger.get_instance(app_state)
        
        await logger.force_info("Immediate info")
        
        mock_redis.xadd.assert_called()
        AuditLogger._instance = None
    
    @pytest.mark.asyncio
    async def test_force_error_immediate(self, mock_redis):
        """Test that force_error publishes immediately."""
        AuditLogger._instance = None
        app_state = MagicMock()
        app_state.redis = mock_redis
        mock_redis.xadd = AsyncMock()
        
        logger = AuditLogger.get_instance(app_state)
        
        await logger.force_error("Critical error")
        
        mock_redis.xadd.assert_called()
        AuditLogger._instance = None
    
    @pytest.mark.asyncio
    async def test_log_exception(self, mock_redis):
        """Test logging an exception."""
        AuditLogger._instance = None
        app_state = MagicMock()
        app_state.redis = mock_redis
        mock_redis.xadd = AsyncMock()
        
        logger = AuditLogger.get_instance(app_state)
        
        await logger.log_exception(
            context="Authentication",
            func_name="authenticate",
            exception=ValueError("Test error")
        )
        
        mock_redis.xadd.assert_called()
        AuditLogger._instance = None


class TestModuleFunctions:
    """Tests for module-level functions."""
    
    @pytest.mark.asyncio
    async def test_init_audit_logger(self, mock_redis):
        """Test init_audit_logger function."""
        AuditLogger._instance = None
        
        app_state = MagicMock()
        app_state.redis = mock_redis
        
        with patch.object(AuditLogger, 'start', new_callable=AsyncMock):
            logger = await init_audit_logger(app_state)
            
            assert logger is not None
    
    @pytest.mark.asyncio
    async def test_shutdown_audit_logger(self, mock_redis):
        """Test shutdown_audit_logger function."""
        AuditLogger._instance = None
        
        app_state = MagicMock()
        app_state.redis = mock_redis
        
        import app.audit_logs.redis_logger as module
        module.global_logger = AuditLogger.get_instance(app_state)
        module.global_logger.buffer = MagicMock()
        module.global_logger.buffer.stop = AsyncMock()
        
        await shutdown_audit_logger()
    
    def test_get_audit_logger(self, mock_redis):
        """Test get_audit_logger dependency."""
        AuditLogger._instance = None
        
        app_state = MagicMock()
        app_state.redis = mock_redis
        
        logger = get_audit_logger(app_state)
        
        assert logger is not None
    
    def test_background_logger(self):
        """Test background_logger dependency."""
        import app.audit_logs.redis_logger as module
        module.global_logger = MagicMock()
        
        background_tasks = MagicMock()
        logger = background_logger(background_tasks)
        
        assert logger is not None


class TestAuditLoggingMiddleware:
    """Tests for AuditLoggingMiddleware class."""
    
    @pytest.mark.asyncio
    async def test_middleware_sets_logger_context(self):
        """Test that middleware sets logger context for HTTP requests."""
        AuditLogger._instance = None
        
        mock_app = AsyncMock()
        mock_scope = {
            "type": "http",
            "app": MagicMock()
        }
        mock_scope["app"].state = MagicMock()
        mock_scope["app"].state.redis = AsyncMock()
        
        middleware = AuditLoggingMiddleware(mock_app)
        
        await middleware(mock_scope, AsyncMock(), AsyncMock())
        
        mock_app.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_middleware_passes_through_non_http(self):
        """Test that middleware passes through non-HTTP requests."""
        mock_app = AsyncMock()
        mock_scope = {"type": "websocket"}
        
        middleware = AuditLoggingMiddleware(mock_app)
        
        await middleware(mock_scope, AsyncMock(), AsyncMock())
        
        mock_app.assert_called_once()
