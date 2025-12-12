SELECT 
    otp_secret, 
    updated_at,
    CASE 
        WHEN updated_at IS NOT NULL 
             AND EXTRACT(EPOCH FROM ($3 - last_used_at)) < 45
        THEN true 
        ELSE false 
    END as is_replayed
FROM otp_secrets
WHERE user_email = $1 
  AND issuer = $2 
  AND is_active = TRUE
