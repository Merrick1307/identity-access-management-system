# AUTH User queries
fetch_user = """SELECT * FROM users WHERE email = $1 AND tenant_id = $2"""
fetch_user_policy = """
                    SELECT policy_id, policy FROM user_policies 
                    WHERE user_id = $1 
                    AND tenant_id = $2
                    AND (
                        (policy -> 'conditions' ->> 'validity_time')::timestamptz >= NOW() 
                        OR NOT (policy -> 'conditions' ? 'validity_time')
                    )"""
fetch_user_with_policy = """
    SELECT 
        u.*,
        up.policy_id,
        up.policy
    FROM users u
    LEFT JOIN user_policies up ON u.id = up.user_id 
        AND (
            (up.policy -> 'conditions' ->> 'validity_time')::timestamptz >= NOW() 
            OR NOT (up.policy -> 'conditions' ? 'validity_time')
        )
    WHERE u.email = $1
"""
fetch_user_condition = """
        SELECT (policy -> 'condition') - 'validity_time' as condition
        FROM user_policies 
        WHERE user_id = $1 AND tenant_id = $2 AND policy ->> 'resource' = $3
        """

check_modified = """SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND last_modified > $2)"""

fetch_user_with_policy_for_refresh = """
    SELECT 
        u.*,
        (u.last_modified > $2),
        up.policy_id,
        up.policy
    FROM users u
    LEFT JOIN user_policies up ON u.id = up.user_id 
        AND (
            (up.policy -> 'conditions' ->> 'validity_time')::timestamptz >= NOW() 
            OR NOT (up.policy -> 'conditions' ? 'validity_time')
        )
    WHERE u.email = $1
"""