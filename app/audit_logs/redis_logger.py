"""
Audit Logger with Redis Streams
- Async, non-blocking log publishing
- Automatic batching for high throughput
- No DB connection contention
"""
import os
import sys
import threading
import asyncio
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from contextvars import ContextVar

import orjson
import redis.asyncio as redis
from fastapi import BackgroundTasks


# Stream configuration
STREAM_NAME = "audit_logs"
MAX_STREAM_LEN = 1_000_000  # Cap stream at 1M entries (auto-trimmed)

# Context variable for request-scoped logger
_current_audit_logger: ContextVar[Optional['AuditLogger']] = ContextVar(
    'current_audit_logger', default=None
)


class RedisLogBuffer:
    """
    Buffered Redis Stream publisher with automatic flushing.
    - Batches logs to reduce network round-trips
    - Flushes on interval OR when buffer is full
    """
    
    def __init__(
        self, 
        redis_client: redis.Redis,
        stream_name: str = STREAM_NAME,
        buffer_size: int = 50,
        flush_interval: float = 1.0
    ):
        self.redis = redis_client
        self.stream_name = stream_name
        self.buffer_size = buffer_size
        self.flush_interval = flush_interval
        self._buffer: list[Dict[str, Any]] = []
        self._lock = asyncio.Lock()
        self._flush_task: Optional[asyncio.Task] = None
        self._running = False
    
    async def start(self):
        """Start the background flush loop."""
        self._running = True
        self._flush_task = asyncio.create_task(self._flush_loop())
    
    async def stop(self):
        """Stop the flush loop and flush remaining logs."""
        self._running = False
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        # Final flush
        await self._flush()
    
    async def _flush_loop(self):
        """Periodic flush loop."""
        while self._running:
            try:
                await asyncio.sleep(self.flush_interval)
                await self._flush()
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[AuditLog] Flush loop error: {e}")
    
    async def _flush(self):
        """Flush buffer to Redis Stream."""
        async with self._lock:
            if not self._buffer:
                return
            
            batch = self._buffer.copy()
            self._buffer.clear()
        
        # Pipeline for efficiency (single round-trip for all logs)
        try:
            pipe = self.redis.pipeline()
            for log_entry in batch:
                # Redis streams require string values - skip None values entirely
                serialized = {k: (str(v) if not isinstance(v, str) else v)
                             for k, v in log_entry.items() if v is not None}
                # noinspection PyAsyncCall
                pipe.xadd(
                    self.stream_name, 
                    serialized,
                    maxlen=MAX_STREAM_LEN,
                    approximate=True  # Faster, slightly imprecise trimming
                )
            await pipe.execute()
        except Exception as e:
            print(f"[AuditLog] Failed to flush {len(batch)} logs: {e}")
            # Re-add failed logs (with limit to prevent memory issues)
            async with self._lock:
                self._buffer = batch[:100] + self._buffer[:100]
    
    async def publish(self, log_data: Dict[str, Any]):
        """Add log to buffer, flush if full."""
        async with self._lock:
            self._buffer.append(log_data)
            should_flush = len(self._buffer) >= self.buffer_size
        
        if should_flush:
            await self._flush()
    
    async def publish_immediate(self, log_data: Dict[str, Any]):
        """Publish immediately (for critical/error logs)."""
        try:
            # Skip None values entirely to avoid "None" string in Redis
            serialized = {k: (str(v) if not isinstance(v, str) else v)
                         for k, v in log_data.items() if v is not None}
            await self.redis.xadd(
                self.stream_name,
                serialized,
                maxlen=MAX_STREAM_LEN,
                approximate=True
            )
        except Exception as e:
            print(f"[AuditLog] Immediate publish failed: {e}")


class AuditLogger:
    """
    Audit logger using Redis Streams.
    
    Usage:
        logger = AuditLogger.get_instance(app_state)
        logger.info("User logged in", user_id="123")
        await logger.force_error("Critical failure", details={...})
    """
    
    _instance: Optional['AuditLogger'] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if hasattr(self, '_initialized'):
            return
        self._initialized = True
        self.app_state = None
        self.buffer: Optional[RedisLogBuffer] = None
        self.name = "audit"
    
    def _init_logger(self, app_state, name: str = "audit"):
        """Initialize with app state containing Redis client."""
        self.app_state = app_state
        self.name = name
        
        if hasattr(app_state, 'redis') and app_state.redis:
            self.buffer = RedisLogBuffer(app_state.redis)
    
    @classmethod
    def get_instance(cls, app_state=None, name: str = "audit") -> 'AuditLogger':
        if cls._instance is None:
            cls._instance = cls()
        if app_state and not cls._instance.app_state:
            cls._instance._init_logger(app_state, name)
        return cls._instance
    
    async def start(self):
        """Start the buffer flush loop (call from lifespan)."""
        if self.buffer:
            await self.buffer.start()
    
    async def stop(self):
        """Stop and flush remaining logs (call from lifespan)."""
        if self.buffer:
            await self.buffer.stop()
    
    def _build_log_entry(
        self, 
        level: str, 
        message: str, 
        **kwargs
    ) -> Dict[str, Any]:
        """Build a structured log entry."""
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level.upper(),
            "logger": self.name,
            "message": message,
            "module": kwargs.pop("module", None) or __name__,
            "function": kwargs.pop("function", None) or sys._getframe(3).f_code.co_name,
            "line": kwargs.pop("line", None) or sys._getframe(3).f_lineno,
            "thread_id": threading.get_ident(),
            "process_id": os.getpid(),
            "extra": orjson.dumps(kwargs).decode() if kwargs else None
        }

    
    def info(self, message: str, **kwargs):
        """Log INFO level (buffered)."""
        if self.buffer:
            entry = self._build_log_entry("INFO", message, **kwargs)
            asyncio.create_task(self.buffer.publish(entry))
    
    def warning(self, message: str, **kwargs):
        """Log WARNING level (buffered)."""
        if self.buffer:
            entry = self._build_log_entry("WARNING", message, **kwargs)
            asyncio.create_task(self.buffer.publish(entry))
    
    def debug(self, message: str, **kwargs):
        """Log DEBUG level (buffered)."""
        if self.buffer:
            entry = self._build_log_entry("DEBUG", message, **kwargs)
            asyncio.create_task(self.buffer.publish(entry))
    
    def error(self, message: str, **kwargs):
        """Log ERROR level (buffered, but triggers flush)."""
        if self.buffer:
            entry = self._build_log_entry("ERROR", message, **kwargs)
            asyncio.create_task(self.buffer.publish(entry))
    
    async def force_info(self, message: str, **kwargs):
        """Log INFO immediately (awaited)."""
        if self.buffer:
            entry = self._build_log_entry("INFO", message, **kwargs)
            await self.buffer.publish_immediate(entry)
    
    async def force_warning(self, message: str, **kwargs):
        """Log WARNING immediately (awaited)."""
        if self.buffer:
            entry = self._build_log_entry("WARNING", message, **kwargs)
            await self.buffer.publish_immediate(entry)
    
    async def force_error(self, message: str, **kwargs):
        """Log ERROR immediately (awaited)."""
        if self.buffer:
            entry = self._build_log_entry("ERROR", message, **kwargs)
            await self.buffer.publish_immediate(entry)
    
    async def force_log(self, level: str, message: str, **kwargs):
        """Log at specified level immediately."""
        if self.buffer:
            entry = self._build_log_entry(level, message, **kwargs)
            await self.buffer.publish_immediate(entry)

    
    def audit(
        self, 
        action: str, 
        user_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        resource: Optional[str] = None,
        decision: Optional[str] = None,
        **kwargs
    ):
        """
        Log an audit event (buffered).
        
        Example:
            logger.audit(
                action="login",
                user_id="123",
                resource="/token",
                decision="granted",
                ip="192.168.1.1"
            )
        """
        audit_data = {
            "action": action,
            "user_id": user_id,
            "tenant_id": tenant_id,
            "resource": resource,
            "decision": decision,
            **kwargs
        }
        # Filter out None values
        audit_data = {k: v for k, v in audit_data.items() if v is not None}
        self.info(f"AUDIT: {action}", **audit_data)
    
    async def log_exception(
        self, 
        context: str, 
        func_name: str, 
        exception: Exception, 
        **kwargs
    ):
        """Log exception with full context (immediate)."""
        await self.force_error(
            message=str(exception),
            context=context,
            function=func_name,
            error_type=type(exception).__name__,
            **kwargs
        )


global_logger: Optional[AuditLogger] = None


def get_audit_logger(app_state) -> AuditLogger:
    """Dependency to get logger with app state."""
    global global_logger
    if global_logger is None:
        global_logger = AuditLogger.get_instance(app_state)
    return global_logger


async def init_audit_logger(app_state) -> AuditLogger:
    """Initialize and start logger (call from lifespan startup)."""
    global global_logger
    global_logger = AuditLogger.get_instance(app_state)
    await global_logger.start()
    return global_logger


async def shutdown_audit_logger():
    """Flush and stop logger (call from lifespan shutdown)."""
    global global_logger
    if global_logger:
        await global_logger.stop()


def background_logger(background_tasks: BackgroundTasks) -> AuditLogger:
    """FastAPI dependency for per-request logger."""
    global global_logger
    if global_logger is None:
        global_logger = AuditLogger.get_instance()
    return global_logger


class AuditLoggingMiddleware:
    """ASGI middleware to set request-scoped logger context."""
    
    def __init__(self, app):
        self.app = app
    
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            app_state = scope["app"].state
            logger = AuditLogger.get_instance(app_state)
            token = _current_audit_logger.set(logger)
            try:
                await self.app(scope, receive, send)
            finally:
                _current_audit_logger.reset(token)
        else:
            await self.app(scope, receive, send)
