import bcrypt


def hash_password(password: str) -> str:
    """Hash the client_secret with bcrypt.

    Args:
        password (str): The plain text password to hash.

    Returns:
        str: The hashed password as a UTF-8 string.
    """
    salt = bcrypt.gensalt(rounds=10)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')