INSERT INTO user_invitations (id, tenant_id, client_id, email, role, invited_by, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
