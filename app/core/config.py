import os

from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
DATABASE_USER = os.getenv("DATABASE_USER")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")

db_connection_string = f'postgres://{DATABASE_USER}:{DATABASE_PASSWORD}@{DATABASE_URL}'
JWT_SECRET = os.getenv("JWT_SECRET")
OTP_SECRET = os.getenv("OTP_SECRET")
