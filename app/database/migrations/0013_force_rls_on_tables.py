"""
Force Row Level Security for table owner.

Without FORCE, the table owner (app's DB user) bypasses RLS entirely.
This ensures RLS policies are enforced even for the table owner.

Depends on: 0012_enable_rls_tenant_policies
"""
from yoyo import step

__depends__ = {"0012_enable_rls_tenant_policies"}

steps = [
    step(
        """
        ALTER TABLE users FORCE ROW LEVEL SECURITY
        """,
        """
        ALTER TABLE users NO FORCE ROW LEVEL SECURITY
        """
    ),
    step(
        """
        ALTER TABLE user_policies FORCE ROW LEVEL SECURITY
        """,
        """
        ALTER TABLE user_policies NO FORCE ROW LEVEL SECURITY
        """
    ),
    step(
        """
        ALTER TABLE tenants FORCE ROW LEVEL SECURITY
        """,
        """
        ALTER TABLE tenants NO FORCE ROW LEVEL SECURITY
        """
    ),
    step(
        """
        ALTER TABLE tenant_policies FORCE ROW LEVEL SECURITY
        """,
        """
        ALTER TABLE tenant_policies NO FORCE ROW LEVEL SECURITY
        """
    ),
]
