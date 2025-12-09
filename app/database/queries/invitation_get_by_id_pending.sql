SELECT email FROM user_invitations 
WHERE id = $1 AND accepted_at IS NULL AND expires_at > NOW()
