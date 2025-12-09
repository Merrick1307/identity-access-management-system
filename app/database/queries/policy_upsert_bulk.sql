INSERT INTO user_policies (tenant_id, user_id, policy_id, policy)
VALUES ($1, $2, $3, $4)
ON CONFLICT (tenant_id, user_id, policy_id) 
DO UPDATE SET policy = EXCLUDED.policy, last_modified = NOW()
