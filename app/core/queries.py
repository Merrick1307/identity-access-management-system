# AUTH User queries
fetch_user = """SELECT * FROM users WHERE email = $1 AND tenant_id = $2"""
fetch_user_policy = """
                    SELECT * FROM user_policies 
                    WHERE user_id = $1 
                    AND tenant_id = $2
                    AND (
                        (policy -> 'condition' ->> 'validity_time')::timestamptz >= NOW() 
                        OR NOT (policy -> 'condition' ? 'validity_time')
                    )"""
fetch_user_condition = """
        SELECT (policy -> 'condition') - 'validity_time' as condition
        FROM user_policies 
        WHERE user_id = $1 AND tenant_id = $2 AND policy ->> 'resource' = $3
        """
