INSERT INTO users (id, tenant_id, email, password, first_name, last_name, role, is_active, email_verified)
VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, FALSE)
