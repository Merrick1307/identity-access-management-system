from fastapi_mail import ConnectionConfig

from .config import (
    MAIL_FROM, MAIL_USERNAME,
    MAIL_PORT, MAIL_SERVER,
    MAIL_PASSWORD, MAIL_STARTTLS,
    MAIL_SSL_TLS
)

# Initiate email configuration
configuration = ConnectionConfig(
    MAIL_USERNAME = MAIL_USERNAME,
    MAIL_PASSWORD = MAIL_PASSWORD,
    MAIL_FROM = MAIL_FROM,
    MAIL_PORT = MAIL_PORT,
    MAIL_SERVER = MAIL_SERVER,
    MAIL_SSL_TLS = MAIL_SSL_TLS,
    MAIL_STARTTLS = MAIL_STARTTLS,
    USE_CREDENTIALS=True
)