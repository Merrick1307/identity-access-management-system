from yoyo import step

__depends__ = {'0013_force_rls_on_tables'}


steps = [
    step(
        """
        ALTER TABLE authorization_codes
        ALTER COLUMN expires_at TYPE TIMESTAMPTZ,
        ALTER COLUMN created_at TYPE TIMESTAMPTZ;
        """,
        """
        ALTER TABLE authorization_codes
        ALTER COLUMN expires_at TYPE TIMESTAMP,
        ALTER COLUMN created_at TYPE TIMESTAMP;
        """
    )
]