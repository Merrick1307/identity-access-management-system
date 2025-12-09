SELECT up.policy_id, up.user_id, up.tenant_id, up.policy, 
       up.created_at, up.last_modified, u.email
FROM user_policies up
JOIN users u ON up.user_id = u.id
WHERE up.tenant_id = $1
ORDER BY up.created_at DESC
LIMIT $2 OFFSET $3
