from dataclasses import dataclass
from typing import Optional, List
from pydantic import BaseModel, HttpUrl, validator
from enum import Enum


class ResponseType(str, Enum):
    CODE = "code"
    TOKEN = "token"
    ID_TOKEN = "id_token"


class GrantType(str, Enum):
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"
    CLIENT_CREDENTIALS = "client_credentials"
    TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"


class OIDCClient(BaseModel):
    client_id: str
    client_secret: str
    client_name: str
    tenant_id: str
    redirect_uris: List[HttpUrl]
    response_types: List[ResponseType] = [ResponseType.CODE]
    grant_types: List[GrantType] = [GrantType.AUTHORIZATION_CODE]
    scope: str = "openid profile email"
    is_active: bool = True


class AuthorizationRequest(BaseModel):
    client_id: str
    redirect_uri: HttpUrl
    response_type: str = "code"
    scope: str = "openid"
    state: Optional[str] = None
    nonce: Optional[str] = None
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = "S256"

    @validator('response_type')
    def validate_response_type(cls, v):
        valid_types = ['code', 'token', 'id_token', 'code token',
                       'code id_token', 'token id_token', 'code token id_token']
        if v not in valid_types:
            raise ValueError(f'Invalid response_type. Must be one of {valid_types}')
        return v


class TokenRequest(BaseModel):
    grant_type: str
    code: Optional[str] = None
    redirect_uri: Optional[HttpUrl] = None
    client_id: str
    client_secret: str
    refresh_token: Optional[str] = None
    code_verifier: Optional[str] = None
    subject_token: Optional[str] = None
    subject_token_type: Optional[str] = None
    audience: Optional[str] = None
    issuer_hint: Optional[str] = None

    @validator('grant_type')
    def validate_grant_type(cls, v):
        valid_grants = ['authorization_code', 'refresh_token', 'client_credentials', 'urn:ietf:params:oauth:grant-type:token-exchange']
        if v not in valid_grants:
            raise ValueError(f'Invalid grant_type. Must be one of {valid_grants}')
        return v

@dataclass
class TokenResponse:
    access_token: str
    token_type: str = "Bearer"
    expires_in: int = 3600
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None
    scope: Optional[str] = None


@dataclass
class UserInfoResponse:
    sub: str
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    name: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    role: Optional[str] = None
    tenant_id: Optional[str] = None


@dataclass
class SignupRequest:
    email: str
    password: str
    first_name: str
    last_name: str
    invitation_token: Optional[str] = None


@dataclass
class InvitationRequest:
    email: str
    role: Optional[str] = None
    client_id: Optional[str] = None


@dataclass
class InvitationResponse:
    invitation_id: str
    email: str
    expires_at: str
    invitation_link: str


@dataclass
class ScopeItem:
    name: str
    description: str
