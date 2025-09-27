from pydantic import BaseModel, EmailStr


class Authentication(BaseModel):
    email: EmailStr
    password: str