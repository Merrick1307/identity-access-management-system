SELECT * FROM refresh_tokens
WHERE jti = $1
  AND client_id = $2
  AND revoked = FALSE
  AND expires_at > NOW()
