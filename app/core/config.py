import os

from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
DATABASE_USER = os.getenv("DATABASE_USER")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")

db_connection_string = f'postgres://{DATABASE_USER}:{DATABASE_PASSWORD}@{DATABASE_URL}'
JWT_SECRET: str = os.getenv("JWT_SECRET")
OTP_SECRET = os.getenv("OTP_SECRET")
ALGORITHM = os.getenv("ALGORITHM")

MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
MAIL_FROM = os.getenv("MAIL_FROM")
MAIL_PORT = int(os.getenv("MAIL_PORT"))
MAIL_SERVER = os.getenv("MAIL_SERVER")
MAIL_SSL_TLS = bool(int(os.getenv("MAIL_SSL_TLS")))
MAIL_STARTTLS = bool(int(os.getenv("MAIL_STARTTLS")))
