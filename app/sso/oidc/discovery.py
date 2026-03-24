from fastapi import APIRouter, Request
from starlette.responses import JSONResponse

router = APIRouter()


@router.get("/.well-known/openid-configuration")
async def openid_configuration(request: Request):
    """
    OpenID Connect Discovery endpoint
    Returns metadata about the OIDC provider
    """
    base_url = str(request.base_url).rstrip('/')

    return JSONResponse({
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/api/v1/oidc/authorize",
        "token_endpoint": f"{base_url}/api/v1/oidc/token",
        "userinfo_endpoint": f"{base_url}/api/v1/oidc/userinfo",
        "jwks_uri": f"{base_url}/api/v1/oidc/jwks",
        "end_session_endpoint": f"{base_url}/api/v1/oidc/logout",
        "response_types_supported": [
            "code",
            "token",
            "id_token",
            "code token",
            "code id_token",
            "token id_token",
            "code token id_token"
        ],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post"
        ],
        "claims_supported": [
            "sub",
            "email",
            "email_verified",
            "name",
            "given_name",
            "family_name",
            "role",
            "tenant_id"
        ],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "client_credentials"
        ],
        "code_challenge_methods_supported": ["S256", "plain"]
    })