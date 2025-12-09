SELECT id, tenant_id, name, redirect_uris, scopes, is_active, created_at, last_modified
FROM oidc_clients
WHERE tenant_id = $1
ORDER BY created_at DESC
