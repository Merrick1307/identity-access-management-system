SELECT COALESCE((settings->'mfa_enabled')::boolean, false)
FROM tenants 
WHERE id = $1 AND is_active = TRUE
