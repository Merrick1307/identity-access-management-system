"""
Create audit_logs table.

Stores application audit logs for compliance and debugging.
"""
from yoyo import step

steps = [
    step(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
            level VARCHAR(20) NOT NULL,
            logger_name VARCHAR(100) NOT NULL,
            message TEXT NOT NULL,
            module VARCHAR(100),
            function VARCHAR(100),
            line_number INTEGER,
            thread_id BIGINT,
            process_id INTEGER,
            extra_data JSONB,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
        """,
        """
        DROP TABLE IF EXISTS audit_logs CASCADE
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp 
        ON audit_logs(timestamp DESC)
        """,
        """
        DROP INDEX IF EXISTS idx_audit_logs_timestamp
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_logs_level 
        ON audit_logs(level)
        """,
        """
        DROP INDEX IF EXISTS idx_audit_logs_level
        """
    ),
    step(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_logs_extra_gin 
        ON audit_logs USING GIN(extra_data)
        """,
        """
        DROP INDEX IF EXISTS idx_audit_logs_extra_gin
        """
    ),
]
