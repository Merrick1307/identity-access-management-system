import os
from urllib.parse import quote_plus

from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
DATABASE_USER = os.getenv("DATABASE_USER")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")

_password_encoded = quote_plus(DATABASE_PASSWORD) if DATABASE_PASSWORD else ""
db_connection_string = f'postgresql://{DATABASE_USER}:{_password_encoded}@{DATABASE_URL}'
JWT_SECRET: str = os.getenv("JWT_SECRET")
OTP_SECRET = os.getenv("OTP_SECRET")
ENCRYPT_KEY = os.getenv("ENCRYPT_KEY")
ALGORITHM = os.getenv("ALGORITHM")

MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
MAIL_FROM = os.getenv("MAIL_FROM")
MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
MAIL_SERVER = os.getenv("MAIL_SERVER")
MAIL_SSL_TLS = bool(int(os.getenv("MAIL_SSL_TLS", "0")))
MAIL_STARTTLS = bool(int(os.getenv("MAIL_STARTTLS", "1")))

APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000")
APP_NAME = os.getenv("APP_NAME", "Hexalgon IAM")
