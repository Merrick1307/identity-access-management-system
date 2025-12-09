SELECT id, email, role, invited_by, expires_at, created_at, accepted_at
FROM user_invitations 
WHERE tenant_id = $1
ORDER BY created_at DESC
