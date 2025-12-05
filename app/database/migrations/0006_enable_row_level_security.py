"""
Enable Row Level Security (RLS) for tenant isolation.

This migration enables RLS and creates policies to enforce
that users can only access data within their tenant.

Depends on: 0003_create_user_policies
"""
from yoyo import step

__depends__ = {"0003_create_user_policies"}

steps = [
    # Enable RLS on tables
    step(
        """
        ALTER TABLE users ENABLE ROW LEVEL SECURITY
        """,
        """
        ALTER TABLE users DISABLE ROW LEVEL SECURITY
        """
    ),
    step(
        """
        ALTER TABLE user_policies ENABLE ROW LEVEL SECURITY
        """,
        """
        ALTER TABLE user_policies DISABLE ROW LEVEL SECURITY
        """
    ),
    step(
        """
        ALTER TABLE tenants ENABLE ROW LEVEL SECURITY
        """,
        """
        ALTER TABLE tenants DISABLE ROW LEVEL SECURITY
        """
    ),
    
    # Create RLS policies - use DO block to handle existing policies
    step(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies 
                WHERE tablename = 'users' AND policyname = 'tenant_isolation_users'
            ) THEN
                CREATE POLICY tenant_isolation_users ON users
                    FOR ALL
                    USING (tenant_id = current_setting('app.tenant_id', true));
            END IF;
        END $$;
        """,
        """
        DROP POLICY IF EXISTS tenant_isolation_users ON users
        """
    ),
    step(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies 
                WHERE tablename = 'user_policies' AND policyname = 'tenant_isolation_user_policies'
            ) THEN
                CREATE POLICY tenant_isolation_user_policies ON user_policies
                    FOR ALL  
                    USING (tenant_id = current_setting('app.tenant_id', true));
            END IF;
        END $$;
        """,
        """
        DROP POLICY IF EXISTS tenant_isolation_user_policies ON user_policies
        """
    ),
    step(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies 
                WHERE tablename = 'tenants' AND policyname = 'tenant_isolation_tenant_policies'
            ) THEN
                CREATE POLICY tenant_isolation_tenant_policies ON tenants
                    FOR ALL
                    USING (id = current_setting('app.tenant_id', true));
            END IF;
        END $$;
        """,
        """
        DROP POLICY IF EXISTS tenant_isolation_tenant_policies ON tenants
        """
    ),
]
