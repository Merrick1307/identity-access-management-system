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
            -- Drop old ALL policy if exists
            DROP POLICY IF EXISTS tenant_isolation_users ON users;
            
            -- Policy for SELECT/UPDATE/DELETE: requires tenant context
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies 
                WHERE tablename = 'users' AND policyname = 'tenant_isolation_users_read'
            ) THEN
                CREATE POLICY tenant_isolation_users_read ON users
                    FOR SELECT
                    USING (tenant_id = current_setting('app.tenant_id', true));
            END IF;
            
            -- Policy for INSERT: allow when no tenant context (onboarding) or matching tenant
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies 
                WHERE tablename = 'users' AND policyname = 'tenant_users_insert'
            ) THEN
                CREATE POLICY tenant_users_insert ON users
                    FOR INSERT
                    WITH CHECK (
                        current_setting('app.tenant_id', true) IS NULL 
                        OR current_setting('app.tenant_id', true) = ''
                        OR tenant_id = current_setting('app.tenant_id', true)
                    );
            END IF;
            
            -- Policy for UPDATE: requires matching tenant context
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies 
                WHERE tablename = 'users' AND policyname = 'tenant_isolation_users_update'
            ) THEN
                CREATE POLICY tenant_isolation_users_update ON users
                    FOR UPDATE
                    USING (tenant_id = current_setting('app.tenant_id', true));
            END IF;
            
            -- Policy for DELETE: requires matching tenant context
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies 
                WHERE tablename = 'users' AND policyname = 'tenant_isolation_users_delete'
            ) THEN
                CREATE POLICY tenant_isolation_users_delete ON users
                    FOR DELETE
                    USING (tenant_id = current_setting('app.tenant_id', true));
            END IF;
        END $$;
        """,
        """
        DROP POLICY IF EXISTS tenant_isolation_users_read ON users;
        DROP POLICY IF EXISTS tenant_users_insert ON users;
        DROP POLICY IF EXISTS tenant_isolation_users_update ON users;
        DROP POLICY IF EXISTS tenant_isolation_users_delete ON users;
        """
    ),
    step(
        """
        DO $$
        BEGIN
            -- Drop old ALL policy if exists
            DROP POLICY IF EXISTS tenant_isolation_user_policies ON user_policies;
            
            -- Policy for SELECT/UPDATE/DELETE: requires tenant context
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies 
                WHERE tablename = 'user_policies' AND policyname = 'tenant_isolation_user_policies_read'
            ) THEN
                CREATE POLICY tenant_isolation_user_policies_read ON user_policies
                    FOR SELECT
                    USING (tenant_id = current_setting('app.tenant_id', true));
            END IF;
            
            -- Policy for INSERT: allow when no tenant context (onboarding) or matching tenant
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies 
                WHERE tablename = 'user_policies' AND policyname = 'tenant_user_policies_insert'
            ) THEN
                CREATE POLICY tenant_user_policies_insert ON user_policies
                    FOR INSERT
                    WITH CHECK (
                        current_setting('app.tenant_id', true) IS NULL 
                        OR current_setting('app.tenant_id', true) = ''
                        OR tenant_id = current_setting('app.tenant_id', true)
                    );
            END IF;
            
            -- Policy for UPDATE: requires matching tenant context
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies 
                WHERE tablename = 'user_policies' AND policyname = 'tenant_isolation_user_policies_update'
            ) THEN
                CREATE POLICY tenant_isolation_user_policies_update ON user_policies
                    FOR UPDATE
                    USING (tenant_id = current_setting('app.tenant_id', true));
            END IF;
            
            -- Policy for DELETE: requires matching tenant context
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies 
                WHERE tablename = 'user_policies' AND policyname = 'tenant_isolation_user_policies_delete'
            ) THEN
                CREATE POLICY tenant_isolation_user_policies_delete ON user_policies
                    FOR DELETE
                    USING (tenant_id = current_setting('app.tenant_id', true));
            END IF;
        END $$;
        """,
        """
        DROP POLICY IF EXISTS tenant_isolation_user_policies_read ON user_policies;
        DROP POLICY IF EXISTS tenant_user_policies_insert ON user_policies;
        DROP POLICY IF EXISTS tenant_isolation_user_policies_update ON user_policies;
        DROP POLICY IF EXISTS tenant_isolation_user_policies_delete ON user_policies;
        """
    ),
    step(
        """
        DO $$
        BEGIN
            -- Drop old ALL policy if exists (replaced by specific policies)
            DROP POLICY IF EXISTS tenant_isolation_tenant_policies ON tenants;
            
            -- Policy for SELECT/UPDATE/DELETE: requires tenant context
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies 
                WHERE tablename = 'tenants' AND policyname = 'tenant_isolation_tenants_read'
            ) THEN
                CREATE POLICY tenant_isolation_tenants_read ON tenants
                    FOR SELECT
                    USING (id = current_setting('app.tenant_id', true));
            END IF;
            
            -- Policy for INSERT: allow when no tenant context (onboarding) or matching tenant
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies 
                WHERE tablename = 'tenants' AND policyname = 'tenant_allow_insert'
            ) THEN
                CREATE POLICY tenant_allow_insert ON tenants
                    FOR INSERT
                    WITH CHECK (
                        current_setting('app.tenant_id', true) IS NULL 
                        OR current_setting('app.tenant_id', true) = ''
                        OR id = current_setting('app.tenant_id', true)
                    );
            END IF;
            
            -- Policy for UPDATE/DELETE: requires matching tenant context
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies 
                WHERE tablename = 'tenants' AND policyname = 'tenant_isolation_tenants_modify'
            ) THEN
                CREATE POLICY tenant_isolation_tenants_modify ON tenants
                    FOR UPDATE
                    USING (id = current_setting('app.tenant_id', true));
            END IF;
            
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies 
                WHERE tablename = 'tenants' AND policyname = 'tenant_isolation_tenants_delete'
            ) THEN
                CREATE POLICY tenant_isolation_tenants_delete ON tenants
                    FOR DELETE
                    USING (id = current_setting('app.tenant_id', true));
            END IF;
        END $$;
        """,
        """
        DROP POLICY IF EXISTS tenant_isolation_tenants_read ON tenants;
        DROP POLICY IF EXISTS tenant_allow_insert ON tenants;
        DROP POLICY IF EXISTS tenant_isolation_tenants_modify ON tenants;
        DROP POLICY IF EXISTS tenant_isolation_tenants_delete ON tenants;
        """
    ),
]
