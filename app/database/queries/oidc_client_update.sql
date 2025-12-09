UPDATE oidc_clients 
SET name = $3, redirect_uris = $4, scopes = $5, last_modified = NOW()
WHERE id = $1 AND tenant_id = $2
