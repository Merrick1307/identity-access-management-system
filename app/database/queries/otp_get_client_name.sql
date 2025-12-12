SELECT name FROM oidc_clients 
WHERE id = $1 AND tenant_id = $2 AND is_active = TRUE
