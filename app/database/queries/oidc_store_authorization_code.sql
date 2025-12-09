INSERT INTO authorization_codes
(id, code, client_id, user_id, tenant_id, redirect_uri, scope,
 code_challenge, code_challenge_method, nonce, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
