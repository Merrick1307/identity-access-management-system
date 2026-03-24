from typing import Optional, Literal, Any

from pydantic import BaseModel, Field


class IdentityProviderCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    protocol: Literal["oidc", "saml"] = "oidc"
    issuer_url: str
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    discovery_url: Optional[str] = None
    authorization_endpoint: Optional[str] = None
    token_endpoint: Optional[str] = None
    userinfo_endpoint: Optional[str] = None
    jwks_uri: Optional[str] = None
    jwt_validation_secret: Optional[str] = None
    enabled: bool = True
    auto_link: bool = True
    authorization_scopes: str = "openid profile email"
    token_endpoint_auth_method: Literal["client_secret_post", "client_secret_basic"] = "client_secret_post"
    claims_source: Literal["auto", "id_token", "userinfo"] = "auto"
    link_by_email_verified_only: bool = True
    default_role: str = Field(default="member", min_length=1, max_length=50)


class IdentityProviderUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=100)
    protocol: Optional[Literal["oidc", "saml"]] = None
    issuer_url: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    discovery_url: Optional[str] = None
    authorization_endpoint: Optional[str] = None
    token_endpoint: Optional[str] = None
    userinfo_endpoint: Optional[str] = None
    jwks_uri: Optional[str] = None
    jwt_validation_secret: Optional[str] = None
    enabled: Optional[bool] = None
    auto_link: Optional[bool] = None
    authorization_scopes: Optional[str] = None
    token_endpoint_auth_method: Optional[Literal["client_secret_post", "client_secret_basic"]] = None
    claims_source: Optional[Literal["auto", "id_token", "userinfo"]] = None
    link_by_email_verified_only: Optional[bool] = None
    default_role: Optional[str] = Field(default=None, min_length=1, max_length=50)


class IdentityProviderResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    protocol: str
    issuer_url: str
    client_id: Optional[str] = None
    discovery_url: Optional[str] = None
    authorization_endpoint: Optional[str] = None
    token_endpoint: Optional[str] = None
    userinfo_endpoint: Optional[str] = None
    jwks_uri: Optional[str] = None
    enabled: bool
    auto_link: bool
    authorization_scopes: str
    token_endpoint_auth_method: str
    claims_source: str
    link_by_email_verified_only: bool
    default_role: str
    created_at: Optional[str] = None
    last_modified: Optional[str] = None


class FederatedIdentityLinkResponse(BaseModel):
    id: str
    tenant_id: str
    provider_id: str
    user_id: str
    external_subject: str
    external_email: Optional[str] = None
    created_at: Optional[str] = None


class BrokerTokenClaims(BaseModel):
    iss: str
    sub: str
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    name: Optional[str] = None
    aud: Any = None
    scope: Optional[str] = None
