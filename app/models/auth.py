from pydantic import BaseModel, EmailStr


class Authentication(BaseModel):
    email: EmailStr
    tenant_id: str
    password: str