INSERT INTO tenant_policies (id, tenant_id, policies, roles)
VALUES ($1, $2, $3, $4)
ON CONFLICT DO NOTHING
