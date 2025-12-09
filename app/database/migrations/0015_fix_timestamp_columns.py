"""
Fix timestamp columns to use TIMESTAMP WITH TIME ZONE.

Ensures timezone-aware datetimes work correctly with asyncpg.
"""
from yoyo import step

__depends__ = {"0014_alter_timestamp on authorization_codes"}

steps = [
    step(
        """
        ALTER TABLE refresh_tokens 
        ALTER COLUMN expires_at TYPE TIMESTAMPTZ,
        ALTER COLUMN created_at TYPE TIMESTAMPTZ
        """,
        """
        ALTER TABLE refresh_tokens 
        ALTER COLUMN expires_at TYPE TIMESTAMP,
        ALTER COLUMN created_at TYPE TIMESTAMP
        """
    ),
    step(
        """
        ALTER TABLE user_sessions 
        ALTER COLUMN created_at TYPE TIMESTAMPTZ 
        USING created_at AT TIME ZONE 'UTC',
        ALTER COLUMN expires_at TYPE TIMESTAMPTZ 
        USING expires_at AT TIME ZONE 'UTC'
        """,
        """
        ALTER TABLE user_sessions 
        ALTER COLUMN created_at TYPE TIMESTAMP,
        ALTER COLUMN expires_at TYPE TIMESTAMP
        """
    ),
]
