"""
Extend identity_providers for broader OIDC interoperability.

Depends on: 0018_create_identity_providers
"""
from yoyo import step

__depends__ = {"0018_create_identity_providers"}

steps = [
    step(
        "ALTER TABLE identity_providers ADD COLUMN IF NOT EXISTS authorization_scopes TEXT DEFAULT 'openid profile email'",
        "ALTER TABLE identity_providers DROP COLUMN IF EXISTS authorization_scopes",
    ),
    step(
        "ALTER TABLE identity_providers ADD COLUMN IF NOT EXISTS token_endpoint_auth_method VARCHAR(40) DEFAULT 'client_secret_post'",
        "ALTER TABLE identity_providers DROP COLUMN IF EXISTS token_endpoint_auth_method",
    ),
    step(
        "ALTER TABLE identity_providers ADD COLUMN IF NOT EXISTS claims_source VARCHAR(20) DEFAULT 'auto'",
        "ALTER TABLE identity_providers DROP COLUMN IF EXISTS claims_source",
    ),
    step(
        "ALTER TABLE identity_providers ADD COLUMN IF NOT EXISTS link_by_email_verified_only BOOLEAN DEFAULT TRUE",
        "ALTER TABLE identity_providers DROP COLUMN IF EXISTS link_by_email_verified_only",
    ),
    step(
        "ALTER TABLE identity_providers ADD COLUMN IF NOT EXISTS default_role VARCHAR(50) DEFAULT 'member'",
        "ALTER TABLE identity_providers DROP COLUMN IF EXISTS default_role",
    ),
]
