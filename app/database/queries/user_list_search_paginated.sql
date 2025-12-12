SELECT id, email, first_name, last_name, role, is_active, created_at
FROM users
WHERE (email ILIKE $1 OR first_name ILIKE $1 OR last_name ILIKE $1)
ORDER BY created_at DESC
LIMIT $2 OFFSET $3
