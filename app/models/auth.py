from typing import List

from pydantic import BaseModel, EmailStr


class Authentication(BaseModel):
    email: EmailStr
    password: str


class BulkRevokeRequest(BaseModel):
    jtis: List[str]