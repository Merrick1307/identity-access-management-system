INSERT INTO oidc_clients (id, tenant_id, client_secret, name, redirect_uris, scopes, is_active)
VALUES ($1, $2, $3, $4, $5, $6, TRUE)
