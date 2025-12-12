UPDATE tenant_policies
SET policies = $3, roles = $4, last_modified = NOW()
WHERE id = $1 AND tenant_id = $2
