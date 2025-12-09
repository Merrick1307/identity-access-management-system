UPDATE oidc_clients 
SET client_secret = $3, last_modified = NOW()
WHERE id = $1 AND tenant_id = $2
