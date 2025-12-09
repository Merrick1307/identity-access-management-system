SELECT * FROM authorization_codes
WHERE code = $1
  AND client_id = $2
  AND redirect_uri = $3
  AND used = FALSE
  AND expires_at > NOW()
