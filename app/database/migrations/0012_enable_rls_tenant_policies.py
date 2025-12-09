"""
Enable Row Level Security on tenant_policies table.

Depends on: 0008_create_tenant_policies
"""
from yoyo import step

__depends__ = {"0008_create_tenant_policies"}

steps = [
    step(
        """
        ALTER TABLE tenant_policies ENABLE ROW LEVEL SECURITY
        """,
        """
        ALTER TABLE tenant_policies DISABLE ROW LEVEL SECURITY
        """
    ),
    step(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies 
                WHERE tablename = 'tenant_policies' AND policyname = 'tenant_isolation_on_tenant_policies'
            ) THEN
                CREATE POLICY tenant_isolation_on_tenant_policies ON tenant_policies
                    FOR ALL
                    USING (tenant_id = current_setting('app.tenant_id', true))
                    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
            END IF;
        END $$;
        """,
        """
        DROP POLICY IF EXISTS tenant_isolation_on_tenant_policies ON tenant_policies
        """
    ),
]
