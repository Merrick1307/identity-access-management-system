UPDATE user_invitations SET accepted_at = NOW() WHERE id = $1
