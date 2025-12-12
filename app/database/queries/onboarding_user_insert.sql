INSERT INTO users (
    id, tenant_id, email, password, first_name, last_name, role
) VALUES ($1, $2, $3, $4, $5, $6, $7)
