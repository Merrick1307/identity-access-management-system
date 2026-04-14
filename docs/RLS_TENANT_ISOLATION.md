# Row-Level Security And Tenant Isolation Deep Dive

This document explains how HEX IAM uses PostgreSQL Row-Level Security (RLS) and application-level tenant context to protect tenant data.

It is written against the current `v0.2.0` implementation.

Relevant source files:

- `app/database/__init__.py`
- `app/database/migrations/0001_create_tenants.py`
- `app/database/migrations/0002_create_users.py`
- `app/database/migrations/0003_create_user_policies.py`
- `app/database/migrations/0006_enable_row_level_security.py`
- `app/database/migrations/0008_create_tenant_policies.py`
- `app/database/migrations/0012_enable_rls_tenant_policies.py`
- `app/database/migrations/0013_force_rls_on_tables.py`
- `app/database/migrations/0016_fix_rls_for_onboarding.py`
- `app/api/v1/policies.py`
- `app/api/v1/users.py`
- `app/api/v1/tenants.py`
- `app/services/policy_service.py`
- `app/services/tenant_service.py`

---

## Why RLS

HEX IAM is a multi-tenant system. Multiple tenants share the same PostgreSQL database and many of the same tables.

That means most queries need a tenant boundary:

```sql
WHERE tenant_id = $current_tenant
```

Relying only on application code to remember that predicate is risky. A missing tenant filter can become a cross-tenant data exposure.

PostgreSQL Row-Level Security adds a database-enforced boundary. Even if application code issues a broad query, PostgreSQL can restrict the visible rows based on the tenant context set for the current connection.

RLS is defense in depth. It does not replace application authorization, but it reduces the blast radius of query mistakes.

---

## Current RLS Scope

The current migrations enable and force RLS for the core tenant tables:

| Table | RLS status |
| --- | --- |
| `tenants` | Enabled and forced |
| `users` | Enabled and forced |
| `user_policies` | Enabled and forced |
| `tenant_policies` | Enabled and forced |

These tables represent the main tenant identity and policy data.

Newer operational tables such as `user_sessions`, `refresh_tokens`, `oidc_clients`, `authorization_codes`, `identity_providers`, `federated_identities`, and `federation_auth_transactions` are currently protected primarily through application-level tenant predicates in queries and service logic, not the same RLS policy set.

That distinction is important for technical readers and operators.

---

## Tenant Context

The main database dependency is `get_database_pool()` in `app/database/__init__.py`.

It resolves tenant context in this order:

1. `X-TENANT-ID` request header
2. `client_id` query parameter
3. `client_id` form field

If a `client_id` is present, the dependency looks up the tenant:

```python
tenant_id = await temp_conn.fetchval(
    "SELECT tenant_id FROM oidc_clients WHERE id = $1",
    client_id
)
```

After resolving a tenant, it sets PostgreSQL session context on the acquired connection:

```python
await connection.execute(
    "SELECT set_config('app.tenant_id', $1, false)",
    tenant_id
)
```

After the request finishes, it clears the setting:

```python
await connection.execute(
    "SELECT set_config('app.tenant_id', '', false)"
)
```

The RLS policies read this setting through:

```sql
current_setting('app.tenant_id', true)
```

The second argument, `true`, tells PostgreSQL to return `NULL` instead of throwing an error if the setting is missing.

---

## Connection Pools

The app creates two PostgreSQL pools:

```python
app.state.db_pool = await asyncpg.create_pool(...)
app.state.db_owner_pool = await asyncpg.create_pool(...)
```

### `db_pool`

This is the normal application pool. It is used by protected tenant-scoped APIs through `get_database_pool()`.

Every normal request using this pool should have tenant context set before database work happens.

### `db_owner_pool`

This is used by `get_database_pool_no_tenant()`.

It is intended for public or bootstrap flows that cannot start with an existing tenant context, such as tenant onboarding.

This pool is more sensitive. It should be used sparingly and only in routes that truly require no pre-existing tenant context.

---

## RLS Policy Pattern

For `users`, RLS policies compare row `tenant_id` with the current setting:

```sql
CREATE POLICY tenant_isolation_users_read ON users
    FOR SELECT
    USING (tenant_id = current_setting('app.tenant_id', true));
```

Update and delete policies follow the same pattern:

```sql
USING (tenant_id = current_setting('app.tenant_id', true))
```

Insert policies are slightly different because onboarding may create a tenant and root user before normal tenant context exists:

```sql
WITH CHECK (
    current_setting('app.tenant_id', true) IS NULL
    OR current_setting('app.tenant_id', true) = ''
    OR tenant_id = current_setting('app.tenant_id', true)
)
```

The same broad pattern applies to:

- `users`
- `user_policies`
- `tenants`
- `tenant_policies`

---

## FORCE ROW LEVEL SECURITY

Enabling RLS is not always enough.

In PostgreSQL, table owners can bypass RLS unless RLS is forced.

Migration `0013_force_rls_on_tables.py` applies:

```sql
ALTER TABLE users FORCE ROW LEVEL SECURITY;
ALTER TABLE user_policies FORCE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
ALTER TABLE tenant_policies FORCE ROW LEVEL SECURITY;
```

This is important because the application's database user may own the tables. Without `FORCE ROW LEVEL SECURITY`, the app user could bypass the policies entirely.

---

## Example: Safe Query Shape

A policy endpoint may call a service with the tenant ID from the verified token:

```python
policies = await get_user_policies(
    db,
    user.tenant_id,
    user.user_id,
    logger
)
```

The service query still includes tenant predicates.

That is good. The application should still filter explicitly by tenant.

RLS is the backstop if a query accidentally omits the predicate:

```sql
SELECT * FROM users;
```

With RLS active and tenant context set, PostgreSQL should only return rows visible to the current tenant.

---

## OIDC Client-Derived Tenant Context

Some OIDC flows do not naturally include `X-TENANT-ID`.

For those flows, the app can derive tenant context from `client_id`:

```text
/api/v1/oidc/authorize?client_id=...
/api/v1/oidc/token
```

The dependency queries `oidc_clients` to find the owning tenant.

This is useful because downstream applications integrate through a client ID, not necessarily through a tenant header.

Security implication: client ID resolution must be trusted and exact. Client IDs should be unique and tenant-owned.

---

## Tenant From Token vs Tenant From Header

The current code contains a commented-out helper:

```python
# def validate_tenant_context(jwt_tenant_id: str, header_tenant_id: str):
#     if jwt_tenant_id != header_tenant_id:
#         raise HTTPException(...)
```

This is a useful hardening step and should be enabled where both values exist.

Why it matters:

- RLS context can be set from `X-TENANT-ID`.
- The verified JWT also contains `tenant_id`.
- If these disagree, the request should fail.

Without this validation, a route might verify a token for one tenant while setting database context from another source. Many service calls also use `user.tenant_id`, which reduces risk, but the boundary should be explicit.

Recommended behavior:

```text
if Authorization token contains tenant_id
and X-TENANT-ID is present
and both values differ
then reject with 403
```

For OIDC flows that derive tenant from `client_id`, validate that the authenticated client belongs to the same tenant used for downstream token issuance.

---

## App-Level Authorization Still Matters

RLS answers:

```text
Which tenant rows can this connection see?
```

It does not answer:

```text
Is this user allowed to perform this action?
Is this user an admin?
Can this client use this redirect URI?
Can this user revoke this session?
```

Those remain application-level authorization decisions.

HEX IAM uses:

- JWT verification
- role checks
- embedded policy checks
- route dependencies
- service-level tenant predicates

RLS is an additional database boundary, not the whole security model.

---

## Tables Without Current RLS Coverage

The current RLS migrations do not apply the same RLS policy set to every tenant-scoped table.

Examples of tables that should be reviewed for future RLS coverage:

- `user_sessions`
- `refresh_tokens`
- `oidc_clients`
- `authorization_codes`
- `user_invitations`
- `totp_secrets`
- `identity_providers`
- `federated_identities`
- `federation_auth_transactions`

Many queries against these tables already include `tenant_id` predicates. That is necessary, but it is not the same as database-enforced tenant isolation.

Recommended next step: add RLS policies for all tenant-scoped tables unless there is a clear reason not to.

---

## Onboarding Exception

Tenant onboarding is special.

Before onboarding completes, there is no existing tenant context that can be supplied by an authenticated tenant admin.

The implementation uses `get_database_pool_no_tenant()` for public onboarding routes. That dependency acquires from `db_owner_pool`.

The insert policies for core tables also allow inserts when `app.tenant_id` is missing or empty.

This is a practical bootstrap exception.

Operational recommendation:

- keep no-tenant database access restricted to onboarding and explicitly public flows
- keep those route handlers small and heavily tested
- avoid reusing the owner/no-tenant pool in normal tenant APIs

---

## Testing Tenant Isolation

Good tenant-isolation tests should cover at least two tenants.

Recommended test scenarios:

1. create Tenant A and Tenant B
2. set `app.tenant_id` to Tenant A
3. insert or query users and policies
4. verify Tenant B rows are invisible
5. repeat for update and delete behavior
6. verify missing tenant context does not expose rows
7. verify mismatched token/header tenant is rejected once validation is enabled

The most useful tests are integration-level tests against PostgreSQL because RLS is database behavior.

Unit tests can check dependency and service logic, but they cannot prove actual RLS enforcement unless they execute against a database with the migrations applied.

---

## Operational Checks

Production deployments should make it easy to answer:

- Which tables have RLS enabled?
- Which tables have RLS forced?
- Which policies exist for each tenant-scoped table?
- Which database role does the app use?
- Does the app role own tables?
- Can the app role bypass RLS?
- Which routes use `get_database_pool_no_tenant()`?

Useful inspection queries:

```sql
SELECT schemaname, tablename, rowsecurity, forcerowsecurity
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY tablename;
```

```sql
SELECT schemaname, tablename, policyname, cmd, qual, with_check
FROM pg_policies
ORDER BY tablename, policyname;
```

These should be part of production readiness checks.

---

## Common Mistakes

### Mistake 1: Setting tenant context too late

Tenant context must be set before tenant-scoped queries run.

### Mistake 2: Not clearing tenant context

Connections are pooled. If tenant context is not cleared, a reused connection may carry stale context.

The current dependency clears the setting after yielding.

### Mistake 3: Relying only on RLS

RLS does not replace role checks, policy checks, or route authorization.

### Mistake 4: Forgetting FORCE RLS

If the app user owns the table and RLS is not forced, the app may bypass policies.

### Mistake 5: Letting header tenant override token tenant

Where a verified token exists, tenant context should be validated against token claims.

---

## Recommended Improvements

1. Enable and force RLS on all tenant-scoped tables.
2. Enforce token/header tenant match where both are present.
3. Add a test suite that exercises RLS against a real PostgreSQL database.
4. Make no-tenant database access auditable and rare.
5. Add startup checks that log tables without expected RLS coverage.
6. Document tenant context rules for every public and protected route family.
7. Consider a helper dependency that returns both the database connection and verified tenant context as one object.

---

## Summary

HEX IAM uses PostgreSQL RLS as a defense-in-depth boundary for core tenant data.

The model is:

```text
resolve tenant from header or client_id
set app.tenant_id on the PostgreSQL connection
let RLS restrict visible tenant rows
still enforce application-level authorization
clear tenant context before returning the connection to the pool
```

The current implementation has the right foundation: enabled RLS, forced RLS on core tables, and request-scoped tenant context.

The next hardening step is to extend RLS to every tenant-scoped table and enforce explicit validation between JWT tenant claims and request tenant context.

