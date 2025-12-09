UPDATE user_policies 
SET policy = $4, last_modified = NOW()
WHERE tenant_id = $1 AND user_id = $2 AND policy_id = $3
