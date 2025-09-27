import logging
import json
import os
import sys
import threading
from datetime import datetime
from typing import Optional, Dict, Any
from fastapi import BackgroundTasks
from contextvars import ContextVar
import asyncio

# Context variable to store the current request's audit logger
_current_audit_logger: ContextVar[Optional['AuditLogger']] = ContextVar('current_audit_logger', default=None)


class BackgroundTasksHandler(logging.Handler):
    def __init__(self, app_state, table_name: str = "audit_logs"):
        super().__init__()
        self.app_state = app_state
        self.table_name = table_name
        self.background_tasks = None
        self.fallback_logs = []

    def set_background_tasks(self, background_tasks: BackgroundTasks):
        """Set the background tasks instance for current request."""
        self.background_tasks = background_tasks

        # Process any fallback logs
        if self.fallback_logs:
            for log_data in self.fallback_logs:
                self.background_tasks.add_task(self.safe_write_log, log_data)
            self.fallback_logs.clear()

    async def _write_log(self, log_data: tuple):
        max_retries = 3
        retry_delay = 1

        for attempt in range(max_retries):
            try:
                if not hasattr(self.app_state, 'db_pool') or not self.app_state.db_pool:
                    print(f"Database pool not available, attempt {attempt + 1}")
                    if attempt == max_retries - 1:
                        print(f"Failed to write log after {max_retries} attempts - no database pool")
                        return
                    await asyncio.sleep(retry_delay)
                    continue

                async with self.app_state.db_pool.acquire() as conn:
                    await conn.execute(f"""
                        INSERT INTO {self.table_name} 
                        (timestamp, level, logger_name, message, module, function, 
                         line_number, thread_id, process_id, extra_data)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    """, *log_data)
                    return

            except Exception as e:
                print(f"Error writing log (attempt {attempt + 1}): {e}")
                if attempt == max_retries - 1:
                    print(
                        f"Failed to write log after {max_retries} attempts: {log_data[3]}")
                else:
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2

    async def safe_write_log(self, log_data):
        try:
            await self._write_log(log_data)
        except Exception as e:
            print("[ERROR] Background task failed:", e)

    def emit(self, record: logging.LogRecord):
        try:
            extra_data = self._extract_extra_data(record)

            log_data = (
                datetime.fromtimestamp(record.created),
                record.levelname,
                record.name,
                self.format(record),
                record.module,
                record.funcName,
                record.lineno,
                record.thread,
                record.process,
                json.dumps(extra_data) if extra_data else None
            )

            if self.background_tasks:
                self.background_tasks.add_task(self.safe_write_log, log_data)
            else:
                # Store for later processing when background_tasks becomes available
                self.fallback_logs.append(log_data)
                if len(self.fallback_logs) > 100:
                    self.fallback_logs.pop(0)

        except Exception as e:
            self.handleError(record)

    def _extract_extra_data(self, record: logging.LogRecord) -> Dict[str, Any]:
        standard_fields = {
            'name', 'msg', 'args', 'levelname', 'levelno',
            'pathname', 'filename', 'module', 'lineno',
            'funcName', 'created', 'msecs', 'relativeCreated',
            'thread', 'threadName', 'processName', 'process',
            'message', 'exc_info', 'exc_text', 'stack_info'
        }

        extra_data = {}
        for key, value in record.__dict__.items():
            if key not in standard_fields:
                try:
                    json.dumps(value)
                    extra_data[key] = value
                except (TypeError, ValueError):
                    extra_data[key] = str(value)

        return extra_data


class AuditLogger:
    """Audit logger with request lifecycle management."""

    def __init__(self, app_state, name: str = "app", table_name: str = "audit_logs"):
        self.app_state = app_state
        self.table_name = table_name
        self.name = name

        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        self.logger.handlers.clear()

        self.db_handler = BackgroundTasksHandler(app_state, table_name)
        self.db_handler.setLevel(logging.INFO)
        self.logger.addHandler(self.db_handler)

        # # Console handler
        # console_handler = logging.StreamHandler()
        # console_handler.setLevel(logging.INFO)
        # console_formatter = logging.Formatter(
        #     '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        # )
        # console_handler.setFormatter(console_formatter)
        # self.logger.addHandler(console_handler)

    def set_background_tasks(self, background_tasks: BackgroundTasks):
        """Set background tasks for current request."""
        self.db_handler.set_background_tasks(background_tasks)

    async def force_log(self, level: str, message: str, **kwargs):
        """Directly write a log to DB, bypassing BackgroundTasks."""
        record = logging.LogRecord(
            name=self.name,
            level=getattr(logging, level.upper(), logging.INFO),
            pathname=__file__,
            lineno=0,
            msg=message,
            args=(),
            exc_info=None
        )

        # Inject kwargs into the record as extra data
        for k, v in kwargs.items():
            setattr(record, k, v)

        extra_data = self.db_handler._extract_extra_data(record)
        log_data = (
            datetime.utcnow(),
            level.upper(),
            self.name,
            message,
            __name__,
            sys._getframe(3).f_code.co_name,
            record.lineno,
            threading.get_ident(),
            os.getpid(),
            json.dumps(extra_data) if extra_data else None
        )

        await self.db_handler._write_log(log_data)

    def info(self, message: str, **kwargs):
        """Log info message with extra context."""
        self.logger.info(message, extra=kwargs)

    def error(self, message: str, **kwargs):
        """Log error message with extra context."""
        self.logger.error(message, extra=kwargs)

    def warning(self, message: str, **kwargs):
        """Log warning message with extra context."""
        self.logger.warning(message, extra=kwargs)

    def debug(self, message: str, **kwargs):
        """Log debug message with extra context."""
        self.logger.debug(message, extra=kwargs)

    async def log_exception(self, context: str, func_name: str, exception: Exception, **kwargs):
        """Specialized method for logging exceptions with full context"""
        error_data = {
            'function': sys._getframe(1).f_code.co_name,
            'error_type': type(exception).__name__,
            'error_message': str(exception),
            'context': context,
            **kwargs
        }

        # Call logger.error directly with exc_info as a separate parameter
        await self.force_log(
            "detailed_exception",
            message=(str(exception)),
            **error_data
        )

    async def force_info(self, message: str, **kwargs):
        await self.force_log("info", message, **kwargs)

    async def force_warning(self, message: str, **kwargs):
        await self.force_log("warning", message, **kwargs)

    async def force_error(self, message: str, **kwargs):
        await self.force_log("error", message, **kwargs)


    def audit(self, action: str, user_id: Optional[str] = None, resource: Optional[str] = None,
              details: Optional[Dict[str, Any]] = None, **kwargs):
        """Specialized audit logging method."""
        audit_data = {
            'action': action,
            'user_id': user_id,
            'resource': resource,
            'details': details or {},
            **kwargs
        }
        self.info(f"AUDIT: {action}", **audit_data)


# Dependency to get audit logger for current request
def get_audit_logger() -> AuditLogger:
    """Get the current request's audit logger."""
    logger = _current_audit_logger.get()
    if logger is None:
        raise RuntimeError("Audit logger not initialized for current request")
    return logger


class AuditLoggingMiddleware:
    def __init__(self, app, table_name: str = "audit_logs"):
        self.app = app
        self.table_name = table_name

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            app_state = scope["app"].state
            logger = AuditLogger(app_state, table_name=self.table_name)

            token = _current_audit_logger.set(logger)

            try:
                await self.app(scope, receive, send)
            finally:
                _current_audit_logger.reset(token)
        else:
            await self.app(scope, receive, send)


def background_logger(background_tasks: BackgroundTasks):
    logger = get_audit_logger()
    logger.set_background_tasks(background_tasks)
    return logger