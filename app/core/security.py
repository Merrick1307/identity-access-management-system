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


def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hashed version using bcrypt.

    Args:
        password: The plain text password to verify
        hashed_password: The hashed password from the database

    Returns:
        bool: True if password matches, False otherwise
    """
    return bcrypt.checkpw(
        password.encode("utf-8"),
        hashed_password.encode("utf-8")
    )