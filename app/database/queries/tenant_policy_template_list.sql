SELECT id, tenant_id, policies, roles, created_at, last_modified
FROM tenant_policies
WHERE tenant_id = $1
ORDER BY created_at DESC
