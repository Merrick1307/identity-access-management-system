# HEX IAM - API Reference

Complete API documentation for integrating with HEX IAM.

---

## Base URL

```
Production: https://your-domain.com/api/v1
Development: http://localhost:8000/api/v1
```

## Swagger Documentation
Available at:
```
http://localhost:8000/docs
```

## Authentication

All protected endpoints require a Bearer token:

```http
Authorization: Bearer <access_token>
X-TENANT-ID: <tenant_id>
```

OIDC client-authenticated flows may instead resolve tenant context from `client_id`.

---

## New federation endpoints

### GET `/federation/providers`
List all trusted identity providers for the current tenant.

### POST `/federation/providers`
Create a trusted identity provider.

Example body:

```json
{
  "name": "Hexalgon SSO",
  "protocol": "oidc",
  "issuer_url": "https://sso.hexalgon.local",
  "discovery_url": "https://sso.hexalgon.local/.well-known/openid-configuration",
  "authorization_endpoint": null,
  "token_endpoint": null,
  "userinfo_endpoint": null,
  "jwks_uri": null,
  "client_id": "iam-broker-client",
  "client_secret": "provider-client-secret",
  "jwt_validation_secret": null,
  "enabled": true,
  "auto_link": true,
  "authorization_scopes": "openid profile email",
  "token_endpoint_auth_method": "client_secret_post",
  "claims_source": "auto",
  "link_by_email_verified_only": true,
  "default_role": "member"
}
```

Field notes:
- `authorization_scopes` controls what IAM requests from the upstream OIDC provider
- `claims_source` may be `auto`, `id_token`, or `userinfo`
- `link_by_email_verified_only=true` is the safer default for auto-linking
- `default_role` is the local IAM role assigned to newly auto-provisioned users

### GET `/federation/providers/{provider_id}`
Return one trusted identity provider.

### PATCH `/federation/providers/{provider_id}`
Update provider settings.

### DELETE `/federation/providers/{provider_id}`
Delete a provider and its link mappings.

### GET `/federation/providers/{provider_id}/links`
List all local user links for one provider.

---

## Updated OIDC token endpoint

### POST `/oidc/token`
Supported grants now include:

- `authorization_code`
- `refresh_token`
- `client_credentials`
- `urn:ietf:params:oauth:grant-type:token-exchange`

### Token exchange request

```http
POST /api/v1/oidc/token
Authorization: Basic <base64(client_id:client_secret)>
Content-Type: application/x-www-form-urlencoded
```

```x-www-form-urlencoded
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<broker_platform_token>
subject_token_type=urn:ietf:params:oauth:token-type:access_token
audience=<client_id>
issuer_hint=https://sso.hexalgon.local
```

### Token exchange response

```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "scope": "openid profile email",
  "id_token": "..."
}
```

### Token exchange behavior

On success IAM will:

1. validate the broker token against a tenant-trusted provider
2. locate or auto-provision a linked tenant-local user
3. load local tenant policies
4. issue an app-scoped IAM token with embedded policy

### Common token exchange errors

- `invalid_client`
- `invalid_request`
- `invalid_grant`
- `unsupported_grant_type`

---

## Backward compatibility

Existing local/native OIDC login continues to work without federation. Tenants can adopt brokered login incrementally by creating an identity provider entry.

---

## Response Format

All API responses use the shared response helpers from `app/core/responses.py`.

### Success Response
```json
{
  "success": true,
  "data": { },
  "message": "Operation completed successfully",
  "timestamp": "2026-03-23T12:34:56.789012+00:00"
}
```

### Error Response
```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable error message",
    "details": []
  },
  "timestamp": "2026-03-23T12:34:56.789012+00:00"
}
```
### Notes
- data may be omitted when there is no response payload
- paginated endpoints return data plus pagination
- some legacy authz responses still manually shape the same envelope instead of using the helper directly

---

# Authentication Endpoints

## POST /authenticate/token

Authenticate user and obtain access token.

### Request
```json
{
  "email": "user@example.com",
  "password": "secure_password"
}
```

### Headers
```http
X-TENANT-ID: tenant_uuid
User-Agent: MyApp/1.0 (optional)
```

### Response (200)
```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "token_type": "Bearer"
  },
  "message": "Authentication successful",
  "timestamp": "2026-03-23T12:34:56.789012+00:00"
}
```

### JWT Token Structure

**Header** (includes JTI for revocation tracking):
```json
{
  "alg": "HS256",
  "typ": "JWT",
  "jti": "550e8400-e29b-41d4-a716-446655440000-1734564290000000000"
}
```

**Payload**:
```json
{
  "sub": "user@example.com",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "iss": "https://hex-iam.example.com",
  "aud": "client_app_id",
  "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
  "role": "admin",
  "policy": {
    "users": 255,
    "documents": 7,
    "settings": 128
  },
  "exp": 1734567890,
  "iat": 1734564290
}
```

> **Note**: The `policy` field contains bitwise-encoded permissions. Value `255` = all permissions, `7` = READ+WRITE+DELETE.

### Error Codes
| Code | Description |
|------|-------------|
| 401 | Invalid credentials |
| 404 | User not found |
| 423 | Account locked |

---

## GET /authenticate/refresh

Refresh access token using current valid token.

### Headers
```http
Authorization: Bearer <access_token>
X-Refresh-Token: Refresh <refresh_token>
```

### Response (200)
```json
{
  "status": "success",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "new_refresh_token",
    "token_type": "bearer",
    "expires_in": 3600
  }
}
```

---

## POST /authenticate/logout

Revoke current token.

### Headers
```http
Authorization: Bearer <access_token>
```

### Response (200)
```json
{
  "status": "success",
  "message": "Successfully logged out"
}
```

---

## POST /authenticate/logout-all

Revoke all active sessions for current user.

### Response (200)
```json
{
  "status": "success",
  "data": {
    "revoked_count": 5
  }
}
```

---

## GET /authenticate/sessions

List all active sessions for current user.

### Response (200)
```json
{
  "status": "success",
  "data": [
    {
      "jti": "session_jti",
      "device_info": {
        "browser": "Chrome",
        "os": "Windows"
      },
      "ip_address": "192.168.1.1",
      "created_at": "2024-01-15T10:30:00Z",
      "expires_at": "2024-01-15T11:30:00Z",
      "is_current": true
    }
  ]
}
```

---

# Authorization Endpoints

## POST /authorize/authorize

Check if user has permission for an action on a resource.

### Request
```json
{
  "user_id": "uuid",
  "action": "write",
  "resource": "documents",
  "resource_id": "doc_123",
  "context": {
    "department": "engineering"
  }
}
```

### Response (200)
```json
{
  "status": "success",
  "data": {
    "allowed": true,
    "reason": "Policy match: documents:write"
  }
}
```

### Action Values
| Action | Bit Value | Description |
|--------|-----------|-------------|
| read | 1 | View resource |
| write | 2 | Create/update resource |
| delete | 4 | Delete resource |
| approve | 8 | Approve requests |
| reject | 16 | Reject requests |
| execute | 32 | Execute operations |
| assign | 64 | Assign to others |
| manage | 128 | Full management |
| export | 256 | Export data |
| import | 512 | Import data |
| activate | 1024 | Activate resource |
| archive | 2048 | Archive resource |

---

## POST /authorize/batch

Check multiple permissions in a single request (optimized).

### Request
```json
{
  "user_id": "uuid",
  "checks": [
    {"action": "read", "resource": "documents"},
    {"action": "write", "resource": "documents"},
    {"action": "approve", "resource": "requests"}
  ]
}
```

### Response (200)
```json
{
  "status": "success",
  "data": {
    "results": {
      "documents:read": true,
      "documents:write": true,
      "requests:approve": false
    }
  }
}
```

---

# OIDC Endpoints

## GET /oidc/authorize

Initiate OAuth2/OIDC authorization flow.

### Query Parameters
| Parameter | Required | Description |
|-----------|----------|-------------|
| client_id | Yes | Registered client ID |
| redirect_uri | Yes | Callback URL |
| response_type | Yes | `code` or `token` |
| scope | Yes | `openid profile email` |
| state | Yes | CSRF protection state |
| nonce | No | For ID token validation |

### Example
```
GET /oidc/authorize?client_id=beams&redirect_uri=https://app.com/callback&response_type=code&scope=openid%20profile%20email&state=xyz123
```

### Response
Redirects to login page, then to redirect_uri with code or tokens.

---

## POST /oidc/token

Exchange authorization code for tokens.

### Request (Authorization Code)
```json
{
  "grant_type": "authorization_code",
  "code": "auth_code_here",
  "redirect_uri": "https://app.com/callback",
  "client_id": "beams",
  "client_secret": "secret"
}
```

### Request (Refresh Token)
```json
{
  "grant_type": "refresh_token",
  "refresh_token": "refresh_token_here",
  "client_id": "beams",
  "client_secret": "secret"
}
```

### Response (200)
```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh...",
  "id_token": "eyJ...",
  "scope": "openid profile email"
}
```

---

## POST /oidc/introspect

OAuth 2.0 token introspection endpoint (RFC 7662-style) for access and refresh tokens.

### Client Authentication
Supports:
- `client_secret_basic` (HTTP Basic auth header)
- `client_secret_post` (`client_id` + `client_secret` in request body)

### Request
```json
{
  "token": "access_or_refresh_token",
  "token_type_hint": "access_token"
}
```

Use `token_type_hint=refresh_token` when introspecting refresh tokens.

### Response (active access token)
```json
{
  "active": true,
  "scope": "openid profile email",
  "client_id": "client_abc123",
  "username": "user@example.com",
  "token_type": "access_token",
  "exp": 1760000000,
  "iat": 1759996400,
  "sub": "user@example.com",
  "aud": "client_abc123",
  "iss": "https://hex-iam.example.com",
  "jti": "user-1-1759996400000000000",
  "tenant_id": "tenant_uuid"
}
```

### Response (inactive token)
```json
{
  "active": false
}
```

### Response (active refresh token)
```json
{
  "active": true,
  "client_id": "client_abc123",
  "token_type": "refresh_token",
  "sub": "user_uuid",
  "exp": 1760086400,
  "iat": 1759996400,
  "jti": "refresh-token-jti",
  "tenant_id": "tenant_uuid"
}
```

---

## GET /oidc/userinfo

Get user profile information.

### Headers
```http
Authorization: Bearer <access_token>
```

### Response (200)
```json
{
  "sub": "user_uuid",
  "email": "user@example.com",
  "email_verified": true,
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "tenant_id": "tenant_uuid"
}
```

---

## GET /oidc/logout

End OIDC session.

### Query Parameters
| Parameter | Required | Description |
|-----------|----------|-------------|
| id_token_hint | No | ID token for logout |
| post_logout_redirect_uri | No | Redirect after logout |
| state | No | State parameter |

---

## GET /.well-known/openid-configuration

OpenID Connect discovery document.

### Response (200)
```json
{
  "issuer": "https://hex-iam.example.com",
  "authorization_endpoint": "https://hex-iam.example.com/api/v1/oidc/authorize",
  "token_endpoint": "https://hex-iam.example.com/api/v1/oidc/token",
  "introspection_endpoint": "https://hex-iam.example.com/api/v1/oidc/introspect",
  "userinfo_endpoint": "https://hex-iam.example.com/api/v1/oidc/userinfo",
  "jwks_uri": "https://hex-iam.example.com/api/v1/oidc/jwks",
  "end_session_endpoint": "https://hex-iam.example.com/api/v1/oidc/logout",
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
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
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
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
  "code_challenge_methods_supported": ["S256", "plain"]
}
```

---

# Policy Management

## GET /policies/me

Get current user's policies.

### Response (200)
```json
{
  "status": "success",
  "data": [
    {
      "policy_id": "admin_policy",
      "resources": {
        "users": 255,
        "documents": 7
      },
      "conditions": {
        "time_based": {
          "start": "09:00",
          "end": "18:00"
        }
      }
    }
  ]
}
```

---

## POST /policies/

Create a new policy (admin only).

### Request
```json
{
  "name": "editor_policy",
  "description": "Editor permissions",
  "policy": {
    "documents": 7,
    "comments": 3
  },
  "conditions": {},
  "roles": ["editor"]
}
```

---

## PUT /policies/{policy_id}

Update an existing policy.

---

## DELETE /policies/{policy_id}

Delete a policy.

---

# Tenant Onboarding

## POST /onboarding/tenant/

Create a new tenant with root user.

### Request
```json
{
  "tenant_name": "Acme Corp",
  "domain": "acme.com",
  "root_user": {
    "email": "admin@acme.com",
    "password": "secure_password",
    "first_name": "Admin",
    "last_name": "User"
  },
  "settings": {
    "mfa_required": false,
    "session_ttl": 3600,
    "password_policy": {
      "min_length": 8,
      "require_uppercase": true
    }
  }
}
```

### Response (201)
```json
{
  "status": "success",
  "data": {
    "tenant_id": "uuid",
    "tenant_name": "Acme Corp",
    "root_user_id": "uuid",
    "verification_sent": true
  }
}
```

---

# User Management

Only the following user-management endpoints are currently implemented in the backend:

## GET /users

List users in the current tenant (admin-capable flow).

### Query Parameters
| Parameter | Description |
|-----------|-------------|
| page | Page number (default: 1) |
| page_size | Items per page (default: 20) |
| search | Search by email or name |
| role | Filter by role |
| is_active | Filter by active status |

## GET /users/{user_id}

Get user details by ID within the current tenant.

> The following operations are **not currently implemented as public backend endpoints**:
> - activate user
> - deactivate user
> - admin-triggered password reset
> - `/onboarding/user/`

## Federation admin
- `GET /api/v1/federation/providers`
- `POST /api/v1/federation/providers`
- `GET /api/v1/federation/providers/{provider_id}`
- `PATCH /api/v1/federation/providers/{provider_id}`
- `DELETE /api/v1/federation/providers/{provider_id}`
- `GET /api/v1/federation/providers/{provider_id}/links`

## OIDC federation browser flow
Browser federation is initiated from the normal downstream authorization endpoint:

- `GET /api/v1/oidc/authorize`

Behavior:
- one enabled upstream provider -> IAM redirects upstream automatically
- multiple enabled upstream providers -> IAM renders a provider chooser
- `local_login=1` -> IAM skips upstream federation and shows native login
- callback endpoint:
  - `GET /api/v1/oidc/federation/callback/{provider_id}`

The callback endpoint is for upstream providers and browser redirects. Client applications should not call it directly.

- `GET /api/v1/oidc/authorize`
- `GET /api/v1/oidc/federation/callback/{provider_id}`

## Token exchange
`POST /api/v1/oidc/token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`

---

# Integration Examples

## Python (httpx)

```python
import httpx

class HexIAMClient:
    def __init__(self, base_url: str, tenant_id: str):
        self.base_url = base_url
        self.tenant_id = tenant_id
        self.token = None
    
    async def login(self, email: str, password: str):
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/authenticate/token",
                json={"email": email, "password": password},
                headers={"X-TENANT-ID": self.tenant_id}
            )
            data = response.json()
            self.token = data["data"]["access_token"]
            return self.token
    
    async def authorize(self, action: str, resource: str) -> bool:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/authorize/authorize",
                json={"action": action, "resource": resource},
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "X-TENANT-ID": self.tenant_id
                }
            )
            return response.json()["data"]["allowed"]
```

## JavaScript (fetch)

```javascript
class HexIAMClient {
  constructor(baseUrl, tenantId) {
    this.baseUrl = baseUrl;
    this.tenantId = tenantId;
    this.token = null;
  }

  async login(email, password) {
    const response = await fetch(`${this.baseUrl}/authenticate/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-TENANT-ID': this.tenantId
      },
      body: JSON.stringify({ email, password })
    });
    const data = await response.json();
    this.token = data.data.access_token;
    return this.token;
  }

  async authorize(action, resource) {
    const response = await fetch(`${this.baseUrl}/authorize/authorize`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.token}`,
        'Content-Type': 'application/json',
        'X-TENANT-ID': this.tenantId
      },
      body: JSON.stringify({ action, resource })
    });
    const data = await response.json();
    return data.data.allowed;
  }
}
```

## cURL Examples

### Login
```bash
curl -X POST https://hex-iam.example.com/api/v1/authenticate/token \
  -H "Content-Type: application/json" \
  -H "X-TENANT-ID: your-tenant-id" \
  -d '{"email": "user@example.com", "password": "password"}'
```

### Authorize
```bash
curl -X POST https://hex-iam.example.com/api/v1/authorize/authorize \
  -H "Authorization: Bearer your-access-token" \
  -H "Content-Type: application/json" \
  -H "X-TENANT-ID: your-tenant-id" \
  -d '{"action": "read", "resource": "documents"}'
```

---

# Authorization Modes

## Mode 1: Embedded Policy (Default)

Policies are embedded in the JWT token. Authorization is checked locally without API calls.

**Pros:**
- Zero latency
- No network dependency
- Scales infinitely

**Cons:**
- Policy changes require token refresh
- Token size grows with permissions

**Client Configuration:**
```python
# BEAMS Django settings
HEX_IAM = {
    "LIVE_AUTHZ": False,  # Use embedded policy
}
```

## Mode 2: Live Authorization

Each authorization check calls HEX IAM's API with caching.

**Pros:**
- Real-time policy evaluation
- Immediate revocation support
- ABAC conditions evaluated server-side

**Cons:**
- Network latency (could be mitigated by caching, tokens are compact.)
- Dependency on HEX IAM availability

**Client Configuration:**
```python
HEX_IAM = {
    "LIVE_AUTHZ": True,
    "AUTHZ_CACHE_TTL": 60,  # Cache decisions for 60 seconds
}
```

---

# Error Codes Reference

| HTTP Code | Error Code | Description |
|-----------|------------|-------------|
| 400 | BAD_REQUEST | Invalid request format |
| 401 | UNAUTHORIZED | Missing or invalid token |
| 401 | TOKEN_EXPIRED | Token has expired |
| 401 | TOKEN_REVOKED | Token was revoked |
| 403 | FORBIDDEN | Permission denied |
| 404 | NOT_FOUND | Resource not found |
| 409 | CONFLICT | Resource already exists |
| 422 | VALIDATION_ERROR | Request validation failed |
| 423 | LOCKED | Account is locked |
| 429 | RATE_LIMITED | Too many requests |
| 500 | INTERNAL_ERROR | Server error |
| 503 | SERVICE_UNAVAILABLE | Service temporarily unavailable |

---
