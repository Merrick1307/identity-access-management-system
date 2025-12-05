"""
Audit Logging Module - Redis Streams Backend

Re-exports from redis_logger for backward compatibility.
"""
from app.audit_logs.redis_logger import (
    AuditLogger,
    AuditLoggingMiddleware,
    RedisLogBuffer,
    background_logger,
    get_audit_logger,
    init_audit_logger,
    shutdown_audit_logger,
    STREAM_NAME,
    MAX_STREAM_LEN,
)

__all__ = [
    "AuditLogger",
    "AuditLoggingMiddleware",
    "RedisLogBuffer",
    "background_logger",
    "get_audit_logger",
    "init_audit_logger",
    "shutdown_audit_logger",
    "STREAM_NAME",
    "MAX_STREAM_LEN",
]
