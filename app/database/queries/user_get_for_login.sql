SELECT id, email, password, first_name, last_name, role, email_verified, is_active 
FROM users WHERE email = $1 AND tenant_id = $2
