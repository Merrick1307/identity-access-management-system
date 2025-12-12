INSERT INTO user_policies (tenant_id, user_id, policy_id, policy)
VALUES ($1, $2, $3, $4)
ON CONFLICT DO NOTHING
