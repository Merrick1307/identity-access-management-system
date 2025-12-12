UPDATE otp_secrets SET updated_at = $1 WHERE user_email = $2 AND issuer = $3
