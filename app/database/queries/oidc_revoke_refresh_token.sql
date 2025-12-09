UPDATE refresh_tokens SET revoked = TRUE WHERE jti = $1
