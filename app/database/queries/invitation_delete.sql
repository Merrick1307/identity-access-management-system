DELETE FROM user_invitations 
WHERE id = $1 AND tenant_id = $2 AND accepted_at IS NULL
