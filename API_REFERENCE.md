# HEX IAM - API Reference

Complete API documentation for integrating with HEX IAM.

---

## Base URL

```
Production: https://your-domain.com/api/v1
Development: http://localhost:8000/api/v1
```

## Authentication

All protected endpoints require a Bearer token:

```http
Authorization: Bearer <access_token>
X-TENANT-ID: <tenant_id>
```

---

## Response Format

All responses follow a consistent structure:

### Success Response
```json
{
  "status": "success",
  "message": "Operation completed successfully",
  "data": { ... }
}
```

### Error Response
```json
{
  "status": "error",
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable error message"
  }
}
```

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
  "status": "success",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "token_type": "bearer",
    "expires_in": 3600
  }
}
```

### JWT Payload Structure
```json
{
  "sub": "user@example.com",
  "user_id": "uuid",
  "iss": "https://hex-iam.example.com",
  "aud": "client_app_id",
  "tenant_id": "uuid",
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

## GET /oidc/.well-known/openid-configuration

OpenID Connect discovery document.

### Response (200)
```json
{
  "issuer": "https://hex-iam.example.com",
  "authorization_endpoint": "https://hex-iam.example.com/api/v1/oidc/authorize",
  "token_endpoint": "https://hex-iam.example.com/api/v1/oidc/token",
  "userinfo_endpoint": "https://hex-iam.example.com/api/v1/oidc/userinfo",
  "jwks_uri": "https://hex-iam.example.com/api/v1/oidc/.well-known/jwks.json",
  "response_types_supported": ["code", "token", "id_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["HS256"],
  "scopes_supported": ["openid", "profile", "email"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
  "claims_supported": ["sub", "email", "name", "given_name", "family_name"]
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

## POST /onboarding/user/

Add a user to existing tenant.

### Request
```json
{
  "email": "user@acme.com",
  "password": "secure_password",
  "first_name": "John",
  "last_name": "Doe",
  "role": "user",
  "policies": ["basic_user"]
}
```

---

# User Management

## GET /users/

List users in tenant (admin only).

### Query Parameters
| Parameter | Description |
|-----------|-------------|
| page | Page number (default: 1) |
| limit | Items per page (default: 20) |
| search | Search by email/name |
| role | Filter by role |
| is_active | Filter by status |

---

## GET /users/{user_id}

Get user details.

---

## PUT /users/{user_id}

Update user details.

---

## DELETE /users/{user_id}

Deactivate user.

---

## POST /users/{user_id}/policies

Assign policies to user.

### Request
```json
{
  "policy_ids": ["editor_policy", "viewer_policy"]
}
```

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

