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
