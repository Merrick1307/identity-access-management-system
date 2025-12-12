SELECT id, email, first_name, last_name, role, is_active, 
       email_verified, created_at, last_login
FROM users
WHERE id = $1
