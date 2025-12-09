SELECT redirect_uris FROM oidc_clients
WHERE id = $1 AND is_active = TRUE
