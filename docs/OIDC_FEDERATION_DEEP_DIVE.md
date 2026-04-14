# OIDC And Federation Deep Dive

This document explains HEX IAM's OAuth 2.0, OpenID Connect, and upstream federation implementation.

It is written against the current `v0.2.0` repository.

Relevant source files:

- `app/sso/oidc/discovery.py`
- `app/sso/oidc/endpoints.py`
- `app/sso/oidc/services.py`
- `app/sso/oidc/clients.py`
- `app/sso/oidc/signup.py`
- `app/services/federation_service.py`
- `app/models/federation.py`
- `app/database/migrations/0009_create_oidc_clients.py`
- `app/database/migrations/0010_create_authorization_codes.py`
- `app/database/migrations/0007_create_refresh_tokens.py`
- `app/database/migrations/0018_create_identity_providers.py`
- `app/database/migrations/0019_create_federated_identities.py`
- `app/database/migrations/0020_create_federation_auth_transactions.py`
- `app/database/migrations/0021_extend_identity_providers_for_oidc_interop.py`

---

## Scope

HEX IAM acts as:

1. a tenant-aware OIDC provider for downstream applications
2. a client of upstream OIDC identity providers during federation
3. a broker-token exchange endpoint for converting trusted upstream identity into tenant-local IAM tokens

It is not currently a complete standards-certified identity provider.

The implementation supports practical OAuth/OIDC flows, but some production-hardening work remains, especially around asymmetric signing, richer discovery metadata, full MFA enforcement, and certification-level protocol coverage.

---

## Current OIDC API Surface

The OIDC routers are included under `/api/v1`:

```text
GET  /api/v1/.well-known/openid-configuration
GET  /api/v1/oidc/authorize
POST /api/v1/oidc/login
POST /api/v1/oidc/consent
POST /api/v1/oidc/token
GET  /api/v1/oidc/userinfo
GET  /api/v1/oidc/jwks
GET  /api/v1/oidc/logout
POST /api/v1/oidc/logout
```

OIDC client management is also exposed:

```text
POST   /api/v1/oidc/clients
GET    /api/v1/oidc/clients
GET    /api/v1/oidc/clients/{client_id}
PATCH  /api/v1/oidc/clients/{client_id}
POST   /api/v1/oidc/clients/{client_id}/rotate-secret
DELETE /api/v1/oidc/clients/{client_id}
```

Invitation and signup support live in the OIDC package:

```text
GET    /api/v1/oidc/signup
POST   /api/v1/oidc/signup
POST   /api/v1/oidc/signup/api
POST   /api/v1/oidc/invite
GET    /api/v1/oidc/invitations
DELETE /api/v1/oidc/invitations/{invitation_id}
```

Federation administration lives outside `/oidc`:

```text
GET    /api/v1/federation/providers
POST   /api/v1/federation/providers
GET    /api/v1/federation/providers/{provider_id}
PATCH  /api/v1/federation/providers/{provider_id}
DELETE /api/v1/federation/providers/{provider_id}
GET    /api/v1/federation/providers/{provider_id}/links
```

---

## Discovery Metadata

The discovery endpoint returns provider metadata based on the request base URL.

Current discovery advertises:

```json
{
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
  "grant_types_supported": [
    "authorization_code",
    "refresh_token",
    "client_credentials"
  ],
  "code_challenge_methods_supported": ["S256", "plain"]
}
```

Current caveat: `/api/v1/oidc/token` supports token exchange, but discovery does not advertise:

```text
urn:ietf:params:oauth:grant-type:token-exchange
```

That mismatch should be fixed if clients are expected to discover token exchange automatically.

---

## Local Signing And JWKS

Locally issued tokens are currently HS256-signed.

`create_jwt_token()` in `app/core/jwt_utils.py` uses:

```python
jwt.encode(payload, secret_key, algorithm='HS256', headers=headers)
```

Because HS256 is symmetric, the JWKS endpoint currently returns an empty key set:

```json
{
  "keys": []
}
```

This is accurate for the current local signing model, but it limits interoperability. Many OIDC clients expect an issuer to publish public keys through JWKS and verify RS256 or ES256 signatures.

Recommended next step:

- add key records for local signing keys
- support RS256/ES256 for locally issued tokens
- publish active public keys from `/api/v1/oidc/jwks`
- include `kid` in JWT headers
- support key rotation and overlapping verification windows

---

## OIDC Client Registration

OIDC clients are tenant-owned.

When a client is created:

1. an authenticated tenant admin calls `POST /api/v1/oidc/clients`
2. the backend generates a client ID
3. the backend generates a secure client secret
4. the secret is bcrypt-hashed before storage
5. the plaintext secret is returned once

The client secret helper in `app/sso/oidc/clients.py` uses:

```python
def generate_client_secret() -> str:
    return secrets.token_urlsafe(32)

def hash_client_secret(secret: str) -> str:
    return bcrypt.hashpw(secret.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
```

The API response includes a warning that the client secret cannot be retrieved again.

Client secret rotation creates a new secret, stores its hash, and invalidates the old secret.

---

## Authorization Code Flow

The Authorization Code flow starts at:

```http
GET /api/v1/oidc/authorize
```

Expected query parameters include:

- `client_id`
- `redirect_uri`
- `response_type`
- `scope`
- `state`
- `nonce`
- `code_challenge`
- `code_challenge_method`
- federation-related controls such as `provider_id` and `local_login`

The endpoint validates the client and redirect URI, then decides whether to continue with:

- an existing local IAM browser session
- native IAM login
- upstream federation
- provider chooser page

The local browser session cookie is named:

```text
hex_iam_session
```

The cookie is HTTP-only and stores a JWT session token used by the OIDC browser flow.

After successful login and consent, the system generates an authorization code:

```python
code = OIDCService.generate_authorization_code()
```

It stores the code with:

- client ID
- user ID
- tenant ID
- redirect URI
- scope
- PKCE challenge and method
- nonce
- expiration

The authorization code is then returned to the downstream app through the redirect URI.

---

## PKCE

PKCE is handled in `OIDCService.validate_authorization_code()`.

If the authorization code has a stored `code_challenge`, the token request must provide a `code_verifier`.

For `S256`, the verifier is hashed and base64url encoded:

```python
computed_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode()).digest()
).decode().rstrip('=')
```

The computed challenge must match the stored challenge.

If the challenge method is not `S256`, the current implementation treats the verifier as the computed challenge, supporting `plain`.

Recommended production posture:

- keep `S256`
- avoid `plain` for public clients unless required for compatibility
- enforce PKCE for public clients

---

## Token Endpoint

The token endpoint is:

```http
POST /api/v1/oidc/token
```

It supports both form-encoded and JSON request bodies.

The endpoint first validates the client:

```python
client = await OIDCService.validate_client(db, client_id, client_secret)
```

Client secret verification uses bcrypt:

```python
if not bcrypt.checkpw(client_secret.encode('utf-8'), stored_secret.encode('utf-8')):
    return None
```

Then the implementation dispatches by `grant_type`.

---

## Authorization Code Grant

For:

```text
grant_type=authorization_code
```

The token endpoint validates:

- code
- client ID
- redirect URI
- optional PKCE verifier

It then:

1. marks the code as used
2. loads the local user
3. loads user policies and converts them to the embedded bitmask format
4. issues an access token
5. creates a refresh token
6. creates an ID token if `openid` is in scope

The access token includes:

- `sub`
- `user_id`
- `tenant_id`
- `aud`
- `role`
- `scope`
- embedded `policy`
- `exp`
- `iat`

The current expiration for access tokens in this path is one hour.

---

## Refresh Token Grant

For:

```text
grant_type=refresh_token
```

The token endpoint:

1. validates the refresh token against the client ID
2. rejects expired or revoked refresh tokens
3. revokes the old refresh token
4. reloads user policies
5. issues a new access token
6. creates a new refresh token

Refresh tokens are stored in PostgreSQL by JTI. The current refresh-token lifetime in `OIDCService.create_refresh_token()` is seven days.

This is refresh-token rotation, not reuse of the same refresh token.

---

## Client Credentials Grant

For:

```text
grant_type=client_credentials
```

The token endpoint issues a service-token style access token with:

- `sub` equal to the client ID
- `client_id`
- `aud` equal to the client ID
- `tenant_id`
- `grant_type=client_credentials`
- one-hour expiration

This path is intended for service-to-service use.

---

## Token Exchange Grant

The token endpoint also supports:

```text
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
```

Inputs include:

- `subject_token`
- `audience`
- `issuer_hint`
- authenticated `client_id` and `client_secret`

The current implementation requires the requested audience to match the authenticated client:

```python
if requested_audience and requested_audience != client_id:
    return invalid_target
```

Then it resolves or provisions a federated user:

```python
user, provider, claims = await federation_service.resolve_or_provision_federated_user(
    db=db,
    tenant_id=tenant_id,
    subject_token=subject_token,
    audience=audience,
    issuer_hint=issuer_hint,
)
```

If validation and linking succeed, HEX IAM issues a tenant-scoped IAM access token and refresh token.

This is useful when a downstream application authenticates through an upstream broker first, then exchanges the broker token for an IAM token scoped to the tenant application.

---

## Federation Data Model

The federation migrations add three main tables.

### `identity_providers`

Tenant-local registry of trusted upstream providers.

Important fields:

- `tenant_id`
- `name`
- `protocol`
- `issuer_url`
- `client_id`
- `client_secret`
- `discovery_url`
- `authorization_endpoint`
- `token_endpoint`
- `userinfo_endpoint`
- `jwks_uri`
- `jwt_validation_secret`
- `enabled`
- `auto_link`
- `authorization_scopes`
- `token_endpoint_auth_method`
- `claims_source`
- `link_by_email_verified_only`
- `default_role`

The schema reserves `protocol = 'saml'`, but the service currently rejects non-OIDC providers:

```python
if payload.get('protocol', 'oidc') != 'oidc':
    raise ValueError('Only OIDC identity providers are supported right now')
```

### `federated_identities`

Links an upstream identity to a tenant-local user.

Important fields:

- `tenant_id`
- `provider_id`
- `user_id`
- `external_subject`
- `external_email`

The key design rule: links are tenant-scoped.

### `federation_auth_transactions`

Temporary state for browser-initiated upstream federation.

It stores:

- downstream client ID
- downstream redirect URI
- downstream scope/state/nonce
- PKCE challenge
- upstream provider ID
- upstream state and nonce
- expiration
- consumed timestamp

This lets HEX IAM redirect the user upstream and then resume the original downstream OIDC flow after the upstream callback.

---

## Broker Token Validation

Federation validates upstream tokens through `app/services/federation_service.py`.

There are two validation modes.

### Shared-secret mode

If `jwt_validation_secret` is configured for the provider, the service accepts HS-family tokens:

```python
jwt.decode(
    subject_token,
    jwt_validation_secret,
    algorithms=['HS256', 'HS384', 'HS512'],
    audience=audience,
    issuer=issuer
)
```

This is useful for local development or trusted bootstrap scenarios.

### JWKS/discovery mode

If no shared secret is configured, the service resolves `jwks_uri` directly or through the provider discovery document.

Then it uses `jwt.PyJWKClient` to find the signing key and accepts common RSA/ECDSA algorithms:

```python
jwt.decode(
    subject_token,
    signing_key.key,
    algorithms=['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'],
    audience=audience,
    issuer=issuer
)
```

This is the path expected for standards-based upstream OIDC providers.

---

## Federated User Linking

After upstream token validation, HEX IAM resolves the local user.

The resolver:

1. checks for an existing federated identity link by tenant, provider, and upstream subject
2. if no link exists, optionally finds a local user by email
3. enforces `link_by_email_verified_only` if configured
4. optionally provisions a local user if none exists
5. inserts the federated identity link

The provider controls:

- whether auto-linking is allowed
- whether email must be verified before linking
- default role for newly provisioned users

Tenant scoping is central.

The same upstream `sub` can be linked separately in different tenants. Roles and policies remain tenant-local.

---

## Browser-Initiated Federation

Browser federation starts from the normal downstream authorization endpoint:

```http
GET /api/v1/oidc/authorize
```

The high-level flow is:

```text
downstream app -> HEX IAM /authorize
HEX IAM resolves tenant from client_id
HEX IAM checks local session
if no local session, HEX IAM selects upstream provider
browser redirects to upstream provider
upstream provider redirects back to HEX IAM callback
HEX IAM exchanges upstream code for tokens
HEX IAM validates identity claims
HEX IAM links/provisions local user
HEX IAM creates local browser session
HEX IAM resumes consent/code issuance to downstream app
```

Provider selection behavior:

- if exactly one enabled provider exists, redirect upstream automatically
- if multiple enabled providers exist, render a provider chooser
- if `local_login=1`, force native IAM login

The upstream callback path is:

```text
GET /api/v1/oidc/federation/callback/{provider_id}
```

---

## Native Login And Local Sessions

OIDC browser flows use a local session cookie:

```text
hex_iam_session
```

The helper `_get_current_session()` checks the cookie first, then falls back to a bearer token if present.

The session payload is decoded with audience verification disabled for cookies because HEX IAM created the cookie session itself.

After successful login or federation callback, HEX IAM sets the session cookie and continues the OIDC flow.

Logout deletes the session cookie:

```python
response.delete_cookie("hex_iam_session", path="/")
```

---

## UserInfo

The UserInfo endpoint accepts a bearer token:

```http
GET /api/v1/oidc/userinfo
Authorization: Bearer <access_token>
```

It decodes the token, loads the local user, and returns claims according to the token scopes.

Typical claims include:

- `sub`
- `email`
- `email_verified`
- `name`
- `given_name`
- `family_name`
- `role`
- `tenant_id`

---

## Admin Portal Integration

The admin portal exposes federation and OIDC management workflows:

- register OIDC clients
- rotate client secrets
- configure upstream identity providers
- select scopes and endpoint auth method
- inspect linked federated identities
- manage invitations

The portal uses the same `/api/v1` APIs and is part of the operational story.

---

## Security Notes

### Client secrets

Client secrets are generated with `secrets.token_urlsafe(32)` and bcrypt-hashed before storage.

Plaintext client secrets are shown only at creation or rotation time.

### Redirect URIs

Redirect URI validation is implemented through the OIDC service by checking the client-registered redirect URI list.

Production deployments should avoid wildcards and keep redirect URIs exact.

### PKCE

PKCE is supported. Public clients should be required to use `S256`.

### Token exchange audience

The token exchange path requires requested audience to match the authenticated downstream client.

That prevents a client from exchanging an upstream token for another client's audience.

### Federation linking

Auto-linking by email is guarded by provider settings. The default model supports requiring verified upstream email before linking.

---

## Current Limitations

- Local token signing is HS256 only.
- Local JWKS is empty.
- Token exchange is implemented but not advertised in discovery.
- SAML is reserved in the model but not implemented.
- OIDC certification-level conformance is not claimed.
- MFA/TOTP APIs exist, but OIDC/native login flow enforcement still needs tightening.
- Refresh tokens are database-backed but not integrated with the Bloom revocation filter in the same way as access-token JTIs.
- Session cookie hardening should be reviewed for production deployment settings such as `secure`, `samesite`, domain, and environment-specific behavior.

---

## Recommended Next Steps

1. Add RS256/ES256 local signing and publish real JWKS.
2. Add `kid` and key rotation.
3. Decide whether token exchange should be included in discovery metadata.
4. Enforce PKCE for public clients.
5. Add formal OIDC conformance tests.
6. Wire tenant token TTL settings into all token issuance paths.
7. Enforce MFA during login when tenant settings require it.
8. Add provider-specific federation guides.
9. Add integration tests with a real upstream OIDC provider fixture.
10. Harden session cookie settings for production.

---

## Summary

HEX IAM's OIDC and federation layer does three jobs:

- issues tenant-scoped tokens to downstream applications
- manages OAuth/OIDC clients
- converts upstream OIDC identity into local tenant IAM identity

The central design principle is tenant ownership. Downstream clients, local users, policies, and federated identity links are tenant-scoped.

The current implementation is practical and test-covered, but it should be described honestly: strong enough for development and integration work, not yet a fully standards-certified enterprise identity provider.

