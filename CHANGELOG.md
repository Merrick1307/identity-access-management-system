# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-01-27

### Added

#### Policy Life-Cycle Management
- Complete implementation of end-to-end policy lifecycle
- Properly configured events that trigger revocation according to security impact

#### Bug-Fixes
- JWT verification silent bug - leading to broken OAuth flow
- Cross-tenant data leak due to wrong database pool usage in some endpoints
- Hardened database initialization script to ensure the application user is not accidentally setup as superuser (to prevent RLS bypass)

#### Developer Experience
- A second article, more explanatory for security and engineering teams who care about implementation details
- Updated the initial article to reflect current repository state

### Documentation
- docs folder with new more detailed implementation details documentation

[0.1.1]: https://github.com/Merrick1307/identity-access-management-system/releases/tag/v0.1.1


## [0.1.0] - 2025-12-13

### Added

#### Core IAM
- Policy-embedded JWT tokens for O(1) authorization checks
- Multi-tenant architecture with PostgreSQL Row-Level Security (RLS)
- Fine-grained access control with bitwise permission system (12 action types)
- TOTP/MFA support with encrypted secrets and backup codes
- Session management with active session tracking and revocation
- Token revocation using Bloom filter for O(1) JTI lookups
- Async audit logging with Redis Streams and batched PostgreSQL persistence
- Tenant configuration system for MFA, password policies, and session settings
- User onboarding with email verification
- Password hashing with bcrypt

#### OAuth 2.0 / OIDC Identity Provider
- Authorization Code Flow with PKCE support
- Client Credentials Flow for service-to-service authentication
- Refresh Token Flow
- OpenID Connect Discovery endpoint (`/.well-known/openid-configuration`)
- UserInfo endpoint (OpenID Connect compliant)
- Full CRUD operations for OAuth client management
- User consent screen for permission approval
- Scope-based access control (openid, profile, email)

#### Performance Optimizations
- LRU token cache with 10,000 token capacity
- Bloom filter for O(1) token revocation checks with 0.0001% false positive rate
- orjson serialization for 10x faster JSON responses
- Async PostgreSQL operations with asyncpg driver
- Prepared SQL statements for query performance
- Externalized SQL queries in `.sql` files for maintainability
- Databases connection pooling

#### API Endpoints
- `/api/v1/authenticate/*` - (service accounts) Authentication endpoints (login, logout, refresh)
- `/api/v1/authorize/*` - Authorization checking endpoints
- `/api/v1/onboarding/*` - Tenant and user onboarding
- `/api/v1/policies/*` - Policy management (CRUD operations)
- `/api/v1/oidc/*` - OAuth 2.0 / OIDC endpoints
- `/api/v1/tenants/*` - Tenant management
- `/api/v1/users/*` - User management
- `/api/v1/otp/*` - TOTP/MFA management

#### Developer Experience
- Docker Compose configuration for one-command deployment
- OpenAPI/Swagger documentation at `/docs`
- Environment-based configuration with `.env.example` template
- Mermaid diagrams for architecture visualization
- Comprehensive README with examples
- API reference documentation
- Architecture documentation with flow diagrams
- Security policy documentation
- Contributing guidelines

#### Database
- PostgreSQL schema with Row-Level Security policies
- Yoyo database migrations
- Tables: tenants, users, user_policies, tenant_policies, user_sessions, refresh_tokens, oidc_clients, authorization_codes, user_invitations, audit_logs
- Indexes for performance optimization
- Tenant isolation through RLS

#### Security
- JWT token generation and verification
- Tenant context isolation per request
- Encrypted sensitive data storage
- Secure password policies
- Session expiration and revocation
- CORS middleware configuration
- Security headers

### Documentation
- README.md with quick start guide
- ARCHITECTURE.md with system design diagrams
- API_REFERENCE.md with endpoint documentation
- CHANGELOG.md with version history
- docs folder with additional documentation
- SECURITY.md with vulnerability reporting process
- CONTRIBUTING.md with development guidelines
- LICENSE (Apache 2.0)

### Infrastructure
- Docker support with multi-stage builds
- Docker Compose setup with PostgreSQL, Redis, and admin portal
- Poetry for dependency management
- Python 3.12+ support
- PostgreSQL 15+ support
- Redis 7+ support

### Known Limitations
- JWT signing uses HS256 (symmetric keys only)
- No built-in rate limiting (requires reverse proxy)
- Single-region deployment only
- No asymmetric key support (RS256/ES256)

[0.1.0]: https://github.com/Merrick1307/identity-access-management-system/releases/tag/v0.1.0