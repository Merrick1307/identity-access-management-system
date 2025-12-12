UPDATE users 
SET email_verified = TRUE 
WHERE id = $1 AND tenant_id = $2
