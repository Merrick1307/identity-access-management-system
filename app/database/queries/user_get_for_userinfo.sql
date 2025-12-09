SELECT id, email, first_name, last_name, role, email_verified 
FROM users WHERE id = $1
