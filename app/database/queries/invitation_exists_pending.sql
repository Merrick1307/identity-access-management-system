SELECT id FROM user_invitations 
WHERE email = $1 AND tenant_id = $2 AND accepted_at IS NULL AND expires_at > NOW()
