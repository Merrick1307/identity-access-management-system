SELECT policy_id, user_id, tenant_id, policy, created_at, last_modified
FROM user_policies
WHERE tenant_id = $1 AND user_id = $2 AND policy_id = $3
