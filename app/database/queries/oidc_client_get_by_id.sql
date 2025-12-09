SELECT id, tenant_id, name, redirect_uris, scopes, is_active, created_at, last_modified
FROM oidc_clients
WHERE id = $1 AND tenant_id = $2
