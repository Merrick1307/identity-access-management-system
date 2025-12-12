SELECT id, email, first_name, last_name, role, is_active, created_at
FROM users
ORDER BY created_at DESC
LIMIT $1 OFFSET $2
