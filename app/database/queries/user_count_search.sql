SELECT COUNT(*) FROM users 
WHERE (email ILIKE $1 OR first_name ILIKE $1 OR last_name ILIKE $1)
