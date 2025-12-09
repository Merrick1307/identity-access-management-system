INSERT INTO refresh_tokens (jti, user_id, tenant_id, client_id, expires_at) 
VALUES ($1, $2, $3, $4, $5)
