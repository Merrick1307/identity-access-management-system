"""
Fix RLS policies to allow tenant onboarding.

The original RLS policies blocked INSERT operations when no tenant context
was set (during onboarding). This migration updates policies to allow
INSERT when app.tenant_id is NULL or empty.

Depends on: 0006_enable_row_level_security
"""
from yoyo import step

__depends__ = {"0006_enable_row_level_security"}

steps = [
    # Fix users table policies
    step(
        """
        DO $$
        BEGIN
            -- Drop old policies
            DROP POLICY IF EXISTS tenant_isolation_users ON users;
            DROP POLICY IF EXISTS tenant_isolation_users_read ON users;
            DROP POLICY IF EXISTS tenant_users_insert ON users;
            DROP POLICY IF EXISTS tenant_isolation_users_update ON users;
            DROP POLICY IF EXISTS tenant_isolation_users_delete ON users;
            
            -- Create new policies
            CREATE POLICY tenant_isolation_users_read ON users
                FOR SELECT
                USING (tenant_id = current_setting('app.tenant_id', true));
                
            CREATE POLICY tenant_users_insert ON users
                FOR INSERT
                WITH CHECK (
                    current_setting('app.tenant_id', true) IS NULL 
                    OR current_setting('app.tenant_id', true) = ''
                    OR tenant_id = current_setting('app.tenant_id', true)
                );
                
            CREATE POLICY tenant_isolation_users_update ON users
                FOR UPDATE
                USING (tenant_id = current_setting('app.tenant_id', true));
                
            CREATE POLICY tenant_isolation_users_delete ON users
                FOR DELETE
                USING (tenant_id = current_setting('app.tenant_id', true));
        END $$;
        """,
        """
        -- Rollback: restore original policy
        DO $$
        BEGIN
            DROP POLICY IF EXISTS tenant_isolation_users_read ON users;
            DROP POLICY IF EXISTS tenant_users_insert ON users;
            DROP POLICY IF EXISTS tenant_isolation_users_update ON users;
            DROP POLICY IF EXISTS tenant_isolation_users_delete ON users;
            
            CREATE POLICY tenant_isolation_users ON users
                FOR ALL
                USING (tenant_id = current_setting('app.tenant_id', true));
        END $$;
        """
    ),
    
    # Fix user_policies table policies
    step(
        """
        DO $$
        BEGIN
            -- Drop old policies
            DROP POLICY IF EXISTS tenant_isolation_user_policies ON user_policies;
            DROP POLICY IF EXISTS tenant_isolation_user_policies_read ON user_policies;
            DROP POLICY IF EXISTS tenant_user_policies_insert ON user_policies;
            DROP POLICY IF EXISTS tenant_isolation_user_policies_update ON user_policies;
            DROP POLICY IF EXISTS tenant_isolation_user_policies_delete ON user_policies;
            
            -- Create new policies
            CREATE POLICY tenant_isolation_user_policies_read ON user_policies
                FOR SELECT
                USING (tenant_id = current_setting('app.tenant_id', true));
                
            CREATE POLICY tenant_user_policies_insert ON user_policies
                FOR INSERT
                WITH CHECK (
                    current_setting('app.tenant_id', true) IS NULL 
                    OR current_setting('app.tenant_id', true) = ''
                    OR tenant_id = current_setting('app.tenant_id', true)
                );
                
            CREATE POLICY tenant_isolation_user_policies_update ON user_policies
                FOR UPDATE
                USING (tenant_id = current_setting('app.tenant_id', true));
                
            CREATE POLICY tenant_isolation_user_policies_delete ON user_policies
                FOR DELETE
                USING (tenant_id = current_setting('app.tenant_id', true));
        END $$;
        """,
        """
        -- Rollback: restore original policy
        DO $$
        BEGIN
            DROP POLICY IF EXISTS tenant_isolation_user_policies_read ON user_policies;
            DROP POLICY IF EXISTS tenant_user_policies_insert ON user_policies;
            DROP POLICY IF EXISTS tenant_isolation_user_policies_update ON user_policies;
            DROP POLICY IF EXISTS tenant_isolation_user_policies_delete ON user_policies;
            
            CREATE POLICY tenant_isolation_user_policies ON user_policies
                FOR ALL
                USING (tenant_id = current_setting('app.tenant_id', true));
        END $$;
        """
    ),
    
    # Fix tenants table policies
    step(
        """
        DO $$
        BEGIN
            -- Drop old policies
            DROP POLICY IF EXISTS tenant_isolation_tenant_policies ON tenants;
            DROP POLICY IF EXISTS tenant_isolation_tenants_read ON tenants;
            DROP POLICY IF EXISTS tenant_allow_insert ON tenants;
            DROP POLICY IF EXISTS tenant_isolation_tenants_modify ON tenants;
            DROP POLICY IF EXISTS tenant_isolation_tenants_delete ON tenants;
            
            -- Create new policies
            CREATE POLICY tenant_isolation_tenants_read ON tenants
                FOR SELECT
                USING (id = current_setting('app.tenant_id', true));
                
            CREATE POLICY tenant_allow_insert ON tenants
                FOR INSERT
                WITH CHECK (
                    current_setting('app.tenant_id', true) IS NULL 
                    OR current_setting('app.tenant_id', true) = ''
                    OR id = current_setting('app.tenant_id', true)
                );
                
            CREATE POLICY tenant_isolation_tenants_modify ON tenants
                FOR UPDATE
                USING (id = current_setting('app.tenant_id', true));
                
            CREATE POLICY tenant_isolation_tenants_delete ON tenants
                FOR DELETE
                USING (id = current_setting('app.tenant_id', true));
        END $$;
        """,
        """
        -- Rollback: restore original policy
        DO $$
        BEGIN
            DROP POLICY IF EXISTS tenant_isolation_tenants_read ON tenants;
            DROP POLICY IF EXISTS tenant_allow_insert ON tenants;
            DROP POLICY IF EXISTS tenant_isolation_tenants_modify ON tenants;
            DROP POLICY IF EXISTS tenant_isolation_tenants_delete ON tenants;
            
            CREATE POLICY tenant_isolation_tenant_policies ON tenants
                FOR ALL
                USING (id = current_setting('app.tenant_id', true));
        END $$;
        """
    ),
]
