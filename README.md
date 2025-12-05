# HEX IAM - Policy-Embedded Identity & Access Management System

A high-performance, multi-tenant Identity and Access Management (IAM) system built with FastAPI, featuring policy-embedded JWT tokens, fine-grained access control, and Redis-backed audit logging.

## Features

- **Multi-Tenant Architecture** - PostgreSQL Row-Level Security (RLS) for tenant isolation
- **Policy-Embedded JWT** - User policies embedded in tokens for O(1) authorization checks
- **Fine-Grained Access Control** - Bitwise permission system with 12 action types
- **High-Performance Responses** - `orjson` serialization
- **Async Audit Logging** - Redis Streams with batched writes, zero request blocking
- **Token Revocation** - Bloom filter for O(1) JTI lookups
- **LRU Token Cache** - 10,000 token cache for repeated verifications

## Tech Stack

| Component | Technology |
|-----------|------------|
| Framework | FastAPI 0.100+ |
| Database | PostgreSQL 15+ with asyncpg |
| Cache/Queue | Redis 7+ with redis-py async |
| Auth | PyJWT, bcrypt |
| Serialization | orjson |
| Token Revocation | rbloom (Bloom filter) |

## Quick Start

### Prerequisites

- Python 3.11+
- PostgreSQL 15+
- Redis 7+

### Installation

```bash
# Clone repository
git clone https://github.com/your-org/hex-iam.git
cd hex-iam

# Install dependencies
pip install poetry
poetry install

# Configure environment
cp .env.example .env
# Edit .env with your database credentials
```

### Environment Variables

```env
DATABASE_URL=localhost:5432/hexiam
DATABASE_USER=postgres
DATABASE_PASSWORD=your_password
JWT_SECRET=your-256-bit-secret
ALGORITHM=HS256
OTP_SECRET=your-otp-secret
REDIS_URL=redis://localhost:6379

# Email (optional)
MAIL_USERNAME=your@email.com
MAIL_PASSWORD=app_password
MAIL_FROM=noreply@yourapp.com
MAIL_PORT=587
MAIL_SERVER=smtp.gmail.com
MAIL_SSL_TLS=0
MAIL_STARTTLS=1
```

### Run

```bash
# Development
poetry run uvicorn app.main:app --reload

# Production
poetry run uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

---

## API Reference

Base URL: `http://localhost:8000/api/v1`

### Authentication

#### Login - Get Access Token

```http
POST /api/v1/authenticate/token
```

**Headers:**
```
X-TENANT-ID: your-tenant-uuid
Content-Type: application/json
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "token_type": "Bearer"
  },
  "message": "Authentication successful",
  "timestamp": "2024-12-05T00:00:00.000000+00:00"
}
```

#### Logout - Revoke Token

```http
POST /api/v1/authenticate/logout
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Logged out successfully",
  "timestamp": "2024-12-05T00:00:00.000000+00:00"
}
```

#### Refresh Token

```http
GET /api/v1/authenticate/refresh
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
  },
  "message": "Token refreshed successfully",
  "timestamp": "2024-12-05T00:00:00.000000+00:00"
}
```

---

### Session Management

#### List Active Sessions

```http
GET /api/v1/authenticate/sessions
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": [
    {
      "jti": "user123-1701734400000000000",
      "device_info": {"user_agent": "Mozilla/5.0..."},
      "ip_address": "192.168.1.1",
      "created_at": "2024-12-05T00:00:00+00:00",
      "expires_at": "2024-12-05T01:00:00+00:00"
    }
  ],
  "message": "Found 1 active sessions",
  "timestamp": "2024-12-05T00:00:00.000000+00:00"
}
```

#### Logout All Sessions (Bulk Revocation)

```http
POST /api/v1/authenticate/logout-all
```

Revokes ALL active sessions for the current user - JTIs are added to Bloom filter.

**Response (200 OK):**
```json
{
  "success": true,
  "data": {"revoked_count": 5},
  "message": "Revoked 5 sessions",
  "timestamp": "2024-12-05T00:00:00.000000+00:00"
}
```

#### Logout Other Sessions

```http
POST /api/v1/authenticate/logout-others
```

Revokes all sessions except the current one.

**Response (200 OK):**
```json
{
  "success": true,
  "data": {"revoked_count": 4},
  "message": "Revoked 4 other sessions",
  "timestamp": "2024-12-05T00:00:00.000000+00:00"
}
```

#### Revoke Specific Session

```http
DELETE /api/v1/authenticate/sessions/{jti}
```

**Response:** `204 No Content`

---

### Authorization

#### Check Permission

```http
POST /api/v1/authorize/authorize
```

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "action": "read",
  "resource": "documents",
  "grant_type": "fga",
  "check_condition": false
}
```

**Parameters:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| action | string | Yes | Permission action (read, write, delete, etc.) |
| resource | string | Yes | Resource identifier |
| grant_type | string | No | `fga` (fine-grained) or `rba` (role-based). Default: `fga` |
| check_condition | bool | No | Whether to evaluate policy conditions |
| conditions_to_check | object | Conditional | Required if `check_condition` is true |

**Available Actions:**
```
read, write, delete, approve, reject, execute, 
assign, manage, export, import, activate, archive
```

**Response (200 OK):**
```json
true   // or false
```

---

### Onboarding

#### Create New Tenant

```http
POST /api/v1/onboarding/tenant/
```

**Request Body:**
```json
{
  "tenant": {
    "name": "Acme Corporation",
    "domain": "acme.com",
    "root": "admin@acme.com"
  },
  "user": {
    "email": "admin@acme.com",
    "password": "SecurePass123!",
    "first_name": "John",
    "last_name": "Doe",
    "role": "root"
  },
  "tenant_policies": [
    {
      "policy_id": "custom_policy",
      "policy": {
        "resource": "reports",
        "actions": ["read", "export"],
        "conditions": {}
      }
    }
  ]
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "data": {
    "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
    "user_id": "550e8400-e29b-41d4-a716-446655440001",
    "tenant_name": "Acme Corporation",
    "admin_email": "admin@acme.com",
    "verification_email_sent": true,
    "message": "Successfully created new tenant - root: admin@acme.com"
  },
  "timestamp": "2024-12-05T00:00:00.000000+00:00"
}
```

#### Verify Email

```http
GET /api/v1/onboarding/email/verify?token=<jwt_token>
```

**Response (200 OK):**
```json
{
  "message": "Email verified successfully. You can now log in."
}
```

---

### Policy Management

#### Get My Policies

```http
GET /api/v1/policies/me
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": [
    {
      "policy_id": "admin_access",
      "user_id": "uuid",
      "tenant_id": "uuid",
      "resource": "all",
      "actions": ["manage", "write", "delete"],
      "conditions": null,
      "created_at": "2024-12-05T00:00:00+00:00"
    }
  ],
  "message": "Retrieved 1 policies",
  "timestamp": "2024-12-05T00:00:00.000000+00:00"
}
```

#### Get User Policies (Admin)

```http
GET /api/v1/policies/user/{user_id}
```

#### Create Policy for User

```http
POST /api/v1/policies/user/{user_id}
```

**Request Body:**
```json
{
  "policy_id": "reports_readonly",
  "resource": "reports",
  "actions": ["read", "export"],
  "conditions": {
    "department": "finance"
  }
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "data": {
    "policy_id": "reports_readonly",
    "user_id": "uuid",
    "tenant_id": "uuid",
    "resource": "reports",
    "actions": ["read", "export"],
    "conditions": {"department": "finance"},
    "created_at": "2024-12-05T00:00:00+00:00"
  },
  "message": "Policy 'reports_readonly' created successfully",
  "timestamp": "2024-12-05T00:00:00.000000+00:00"
}
```

#### Update Policy

```http
PUT /api/v1/policies/user/{user_id}/{policy_id}
```

**Request Body:**
```json
{
  "actions": ["read", "write", "export"],
  "conditions": {
    "department": "finance",
    "level": "senior"
  }
}
```

#### Delete Policy

```http
DELETE /api/v1/policies/user/{user_id}/{policy_id}
```

**Response:** `204 No Content`

#### Bulk Assign Policy

```http
POST /api/v1/policies/bulk-assign
```

**Request Body:**
```json
{
  "user_ids": ["uuid1", "uuid2", "uuid3"],
  "policy_id": "viewer_policy",
  "resource": "documents",
  "actions": ["read"],
  "conditions": {}
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "data": {
    "assigned_count": 3,
    "policy_id": "viewer_policy",
    "user_ids": ["uuid1", "uuid2", "uuid3"]
  },
  "message": "Policy assigned to 3 users",
  "timestamp": "2024-12-05T00:00:00.000000+00:00"
}
```

#### Revoke Policy

```http
DELETE /api/v1/policies/revoke/{user_id}/{policy_id}
```

#### List All Tenant Policies (Paginated)

```http
GET /api/v1/policies/tenant?page=1&page_size=20
```

---

## Policy Structure

Policies are embedded in JWT tokens for zero-latency authorization checks.

### Policy Format

```json
{
  "resource": "documents",
  "actions": ["read", "write", "delete"],
  "conditions": {
    "department": "engineering",
    "validity_time": {
      "start": "2024-01-01T00:00:00Z",
      "end": "2024-12-31T23:59:59Z"
    }
  }
}
```

### JWT Token Payload

```json
{
  "sub": "user@example.com",
  "user_id": "uuid",
  "tenant_id": "uuid",
  "role": "admin",
  "policy": {
    "documents": 7,      // READ | WRITE | DELETE = 1 + 2 + 4 = 7
    "reports": 257,      // READ | EXPORT = 1 + 256 = 257
    "all": 255           // Full admin access
  },
  "exp": 1701734400,
  "iat": 1701730800
}
```

### Bitwise Permission Values

| Action | Value | Binary |
|--------|-------|--------|
| READ | 1 | 0000 0000 0001 |
| WRITE | 2 | 0000 0000 0010 |
| DELETE | 4 | 0000 0000 0100 |
| APPROVE | 8 | 0000 0000 1000 |
| REJECT | 16 | 0000 0001 0000 |
| EXECUTE | 32 | 0000 0010 0000 |
| ASSIGN | 64 | 0000 0100 0000 |
| MANAGE | 128 | 0000 1000 0000 |
| EXPORT | 256 | 0001 0000 0000 |
| IMPORT | 512 | 0010 0000 0000 |
| ACTIVATE | 1024 | 0100 0000 0000 |
| ARCHIVE | 2048 | 1000 0000 0000 |

---

## Error Responses

All errors follow this standardized format:

```json
{
  "success": false,
  "error": {
    "code": "UNAUTHORIZED",
    "message": "Token has expired",
    "path": "/api/v1/authorize/authorize",
    "method": "POST"
  },
  "timestamp": "2024-12-05T00:00:00.000000+00:00"
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `UNAUTHORIZED` | 401 | Authentication required or failed |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `VALIDATION_ERROR` | 422 | Invalid request data |
| `DB_CONNECTION_ERROR` | 503 | Database unavailable |
| `INTERNAL_ERROR` | 500 | Unexpected server error |

---

## Database Schema

### Core Tables

- `tenants` - Organization accounts
- `users` - User accounts with tenant association
- `user_policies` - Per-user policy assignments
- `tenant_policies` - Tenant-wide policy templates
- `audit_logs` - Audit trail (populated from Redis)

### Row-Level Security

All tables use PostgreSQL RLS for automatic tenant isolation:

```sql
-- Set tenant context per request
SELECT set_config('app.tenant_id', 'tenant-uuid', true);

-- RLS policy automatically filters
SELECT * FROM users;  -- Only returns current tenant's users
```

---

## Performance


### Optimizations

1. **LRU Token Cache** - 10,000 tokens cached in memory
2. **Bloom Filter** - O(1) revocation check, 0.0001% false positive rate
3. **Redis Streams** - Batched audit writes every 5 seconds
4. **orjson** - 10x faster JSON serialization
5. **asyncpg** - Native PostgreSQL async driver with prepared statements

---

## Project Structure

```
app/
├── api/
│   └── v1/
│       ├── auth.py          # /authenticate endpoints
│       ├── authz.py         # /authorize endpoints
│       └── onboarding.py    # /onboarding endpoints
├── audit_logs/
│   ├── redis_logger.py      # Redis Streams logger
│   └── consumer.py          # Background log processor
├── core/
│   ├── auth.py              # Authentication logic
│   ├── authz.py             # Authorization logic
│   ├── jwt_utils.py         # JWT create/verify
│   ├── responses.py         # Standardized responses
│   └── config.py            # Environment config
├── database/
│   └── __init__.py          # DB schema, pool, lifespan
├── exceptions/
│   ├── database_error_module.py
│   └── http_error_module.py
├── models/                  # Pydantic models
├── services/
│   └── onboarding.py        # Tenant onboarding service
├── sso/
│   └── oidc/                # OIDC IdP (WIP)
└── main.py                  # FastAPI app entry
```


---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request