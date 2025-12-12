from yoyo import step

__depends__ = {"0009_create_oidc_clients"}

steps = [
    step(
        """
        CREATE TABLE totp_secrets (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id VARCHAR(50) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            user_email VARCHAR(255) NOT NULL,
            issuer VARCHAR(255) NOT NULL,
            otp_secret VARCHAR(255) NOT NULL,
            backup_codes TEXT[] NOT NULL,
            is_active BOOLEAN DEFAULT FALSE,
            is_confirmed BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used_at TIMESTAMP,
            UNIQUE(tenant_id, user_email, issuer)
        )
        """,
        """
        DROP TABLE totp_secrets
        """
    ),
    step(
        """
        CREATE INDEX idx_totp_secrets_lookup 
        ON totp_secrets(tenant_id, user_email, issuer) WHERE is_active = TRUE
        """,
        """
        DROP INDEX IF EXISTS idx_totp_secrets_lookup
        """
    )
]
