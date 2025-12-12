SELECT id, tenant_id, policies, roles, created_at, last_modified
FROM tenant_policies
WHERE id = $1 AND tenant_id = $2
