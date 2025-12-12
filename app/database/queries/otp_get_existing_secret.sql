SELECT otp_secret FROM totp_secrets
WHERE tenant_id = $1 AND user_email = $2 AND issuer = $3 AND is_active = TRUE
