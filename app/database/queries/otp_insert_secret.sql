INSERT INTO otp_secrets (tenant_id, user_email, issuer, otp_secret, backup_codes)
VALUES ($1, $2, $3, $4, $5)
RETURNING otp_secret
