# Token Revocation Deep Dive

This document explains how HEX IAM revokes JWT access tokens across workers and deployments.

It is written against the current `v0.2.0` implementation.

Relevant source files:

- `app/main.py`
- `app/core/jwt_utils.py`
- `app/core/auth.py`
- `app/core/token_revocation.py`
- `app/services/session_service.py`
- `app/database/__init__.py`
- `tests/core/test_token_revocation.py`
- `tests/services/test_session_service.py`

---

## Problem

JWTs are normally self-contained. Once a worker verifies the token signature and expiration, the token can be accepted without a database call.

That property is useful for performance, but it makes revocation harder.

If a user logs out, an admin revokes a session, or a sensitive profile change requires re-authentication, the system needs a way to reject an otherwise valid JWT before its `exp` time.

The naive solution is to check a revocation table or Redis key on every request:

```text
request -> verify JWT -> query Redis/PostgreSQL for jti -> allow/deny
```

That works, but it puts a network hop back into the hot path.

HEX IAM avoids that for access-token revocation by keeping a local Bloom filter in each worker.

---

## Current Design

The current revocation design has four pieces:

| Component | Purpose |
| --- | --- |
| JWT `jti` | Unique token identifier used as the revocation key |
| Local Bloom filter | Per-worker O(1) revoked-token membership check |
| Redis Stream | Durable revocation log for replay |
| Redis Pub/Sub | Fast live fan-out to running workers |

The constants are defined in `app/core/token_revocation.py`:

```python
STREAM_NAME = "token:revocations"
PUBSUB_CHANNEL = "hexiam:revocations"
CONSUMER_GROUP = "bloom-sync"
BATCH_SIZE = 100
BLOCK_MS = 1000
```

The Bloom filter is created during application startup in `app/database/__init__.py`:

```python
app.state.bloom_filter = Bloom(
    expected_items=10000000,
    false_positive_rate=0.0001
)
```

That means the current configuration targets:

- 10,000,000 expected revoked token IDs
- `0.0001` false-positive rate

As a percentage, `0.0001` is `0.01%`.

---

## Token Identity

Every normal JWT created by `create_jwt_token()` gets a `jti`.

The current implementation builds the JTI from the user ID and nanosecond timestamp:

```python
user_id = payload.get('user_id') or payload['sub']
jti: str = f"{user_id}-{time.time_ns()}"
headers = {"jti": jti}
payload = {**payload, "jti": jti}
```

The JTI is placed in both:

- JWT header
- JWT payload

The middleware reads the header version without fully decoding the token:

```python
token_header_jti = jwt.get_unverified_header(token).get("jti")
```

That is useful because the revocation check can happen before the full route handler and before the dependency-level JWT payload extraction.

The security boundary is still the signed token. Reading an unverified header is acceptable for locating the revocation key, but the request still needs normal JWT verification before trusted claims are used.

---

## Request-Time Check

Protected requests pass through the HTTP middleware in `app/main.py`.

The simplified logic is:

```python
token_header_jti = jwt.get_unverified_header(token).get("jti")

if not token_header_jti:
    return _unauthorized_response("Token missing JTI")

if token_header_jti in request.app.state.bloom_filter:
    return _unauthorized_response("Token has been revoked")

return await call_next(request)
```

This check is local to the worker.

No Redis or PostgreSQL call is made during the revocation check.

Important detail: the current middleware checks `request.app.state.bloom_filter` directly. It does not call `TokenRevocationManager.is_revoked()`, though the manager exposes that method.

---

## Revocation Write Path

Session revocation flows through `app/services/session_service.py`.

For a single session, the implementation first updates PostgreSQL:

```sql
UPDATE user_sessions
SET revoked_at = NOW(), revoked_reason = $4
WHERE jti = $1
  AND user_id = $2
  AND tenant_id = $3
  AND revoked_at IS NULL
```

If the database update affects a row, the service publishes the revocation:

```python
await revocation_manager.revoke_token(jti, user_id, tenant_id, reason)
```

The revocation manager then performs three actions:

```python
self.bloom.add(jti)
await self.redis.xadd(STREAM_NAME, payload, maxlen=1_000_000)
await self.redis.publish(PUBSUB_CHANNEL, json.dumps({...}))
```

The ordering is intentional:

1. Add to the local Bloom filter immediately.
2. Write to the Redis Stream for durable replay.
3. Publish to Redis Pub/Sub for fast fan-out.

The method returns whether the stream write succeeded. Pub/Sub failure is logged as degraded cross-node sync but does not currently fail the revocation call if the stream write succeeded.

---

## Redis Stream Replay

On startup, `TokenRevocationManager.initialize()` creates the stream consumer group if needed:

```python
await self.redis.xgroup_create(
    STREAM_NAME,
    CONSUMER_GROUP,
    id="0",
    mkstream=True
)
```

Then it replays existing revocations:

```python
entries = await self.redis.xrange(
    STREAM_NAME,
    min=last_id,
    count=BATCH_SIZE
)
```

Every replayed JTI is added to the local Bloom filter.

This is the durable recovery path. A worker that was offline during a revocation can rebuild its local filter by reading the stream at startup.

---

## Redis Pub/Sub Fan-Out

Running workers also subscribe to the Pub/Sub channel:

```python
await pubsub.subscribe(PUBSUB_CHANNEL)
```

When a message arrives, the worker parses the JSON payload and adds the JTI to the local Bloom filter:

```python
data = json.loads(message["data"])
jti = data.get("jti")
if jti and jti not in self.bloom:
    self.bloom.add(jti)
```

This is the live propagation path for all currently running workers.

---

## Important Redis Semantics

Redis Pub/Sub broadcasts a message to every active subscriber.

Redis Stream consumer groups do not broadcast each message to every consumer in the group. A consumer group distributes messages among consumers.

That distinction matters.

The current implementation uses:

```python
await self.redis.xreadgroup(
    CONSUMER_GROUP,
    self.worker_id,
    {STREAM_NAME: ">"},
    count=BATCH_SIZE,
    block=BLOCK_MS
)
```

Because this uses a shared consumer group, a new stream entry is delivered to one consumer in that group, not every worker.

So in the current design:

- Pub/Sub is the live broadcast mechanism.
- Stream replay is the durable recovery mechanism.
- Stream `XREADGROUP` is not sufficient by itself to update every local Bloom filter in every worker.

This should be understood clearly by anyone operating or extending the revocation model.

If the design goal is "every worker live-reads every stream entry," use one of these approaches:

- plain `XREAD` per worker with each worker tracking its own offset
- a unique consumer group per worker or per deployment instance
- periodic full or incremental reconciliation from the stream
- a shared central Redis set lookup for ambiguous Bloom hits, if stronger consistency is needed

The current system relies on Pub/Sub for live fan-out and Stream replay for durability.

---

## Bulk Revocation

Bulk revocation is used for:

- logout from all sessions
- logout from other sessions
- admin bulk revocation
- admin revoke all sessions for a user

The service gets active JTIs from `user_sessions`, sends them through `revoke_user_tokens()`, then updates the database rows.

The current implementation revokes sequentially:

```python
for jti in jtis:
    if await self.revoke_token(jti, user_id, tenant_id, reason):
        count += 1
```

This is simple and easy to reason about. If bulk revocation volume becomes high, the obvious optimization is to pipeline Redis stream writes and Pub/Sub publishes.

---

## Bloom Filter Properties

A Bloom filter can answer set membership in O(1), but it is probabilistic.

It can say:

- definitely not present
- maybe present

For revocation, this maps well:

| Result | Meaning | Security impact |
| --- | --- | --- |
| Definitely not present | Token is not known revoked | Continue to normal JWT verification |
| Maybe present | Treat token as revoked | May force re-authentication |

A false positive denies a valid token. That hurts availability or user experience, but it does not grant unauthorized access.

A false negative would be dangerous. Bloom filters should not produce false negatives when used correctly.

---

## Failure Modes

### Redis Pub/Sub publish fails

The local worker still revokes immediately because it updates its own Bloom filter.

The stream write may still succeed, preserving the revocation for replay.

Other running workers may not learn immediately if they miss Pub/Sub and do not separately read the revocation from a stream path that reaches every worker.

Mitigation options:

- alert on Pub/Sub publish failures
- add periodic reconciliation from `token:revocations`
- use unique stream offsets per worker if stronger live propagation is required

### Redis Stream write fails

The current worker still updates its local Bloom filter, but the durable record may be missing.

That means a restarted worker may not learn this revocation from replay.

The current `revoke_token()` returns `False` if the stream write fails. Callers should treat that as a degraded or failed revocation depending on the security requirement.

### Worker restarts

The worker creates a fresh Bloom filter and replays the stream with `XRANGE`.

This depends on the revocation still being present in the stream.

The stream is capped with:

```python
maxlen=1_000_000
```

If the stream trims older revocations before all related tokens expire, replay may miss them.

### Bloom filter false positive

The request is rejected as revoked.

The user must re-authenticate or refresh through a valid path.

### Bloom filter saturation

As inserted item count exceeds sizing assumptions, false positives increase.

The current repo does not implement a Bloom rebuild job. A production deployment should monitor filter pressure and rebuild from non-expired revocations.

---

## Operational Requirements

Redis ACLs must allow both stream/key operations and Pub/Sub channel access.

The README already calls this out:

```text
user hex-iam on >your-password allcommands allkeys allchannels
```

Without channel permissions, Streams may work while Pub/Sub fails with:

```text
No permissions to access a channel
```

Recommended production monitoring:

- Redis Stream length for `token:revocations`
- Pub/Sub subscriber count for `hexiam:revocations`
- Pub/Sub publish failures
- stream write failures
- number of active sessions
- number of revoked sessions
- authorization 401 rate caused by revocation
- Bloom filter configured capacity
- observed or estimated false-positive rate

---

## Security Notes

The revocation check is not the only token check.

A request must still pass:

- bearer token presence check
- JWT `jti` presence check
- Bloom revocation check
- JWT signature validation
- JWT expiration validation
- route/dependency authorization checks

Reading the unverified JWT header for `jti` is a routing optimization, not a trust boundary.

The trust boundary remains signature verification with the configured JWT secret and allowed algorithm.

---

## Current Gaps And Recommended Improvements

### 1. Add periodic reconciliation

Because shared Redis Stream consumer groups do not broadcast each message to every worker, add a periodic reconciliation task that reads new stream entries since the worker's last seen stream ID.

### 2. Define stream retention by token TTL

The stream cap should be tied to the maximum lifetime of tokens that may still be accepted.

If access tokens live one hour, revocation records must remain replayable for at least that long, plus clock skew and restart windows.

If refresh tokens or longer-lived tokens use the same revocation path, retention must account for those too.

### 3. Expose revocation metrics

Useful metrics:

- stream write success/failure
- Pub/Sub publish success/failure
- Pub/Sub receive count
- local Bloom additions
- rejected requests due to Bloom hit
- stream replay count on startup

### 4. Consider exact fallback for Bloom hits

For some products, false-positive login friction is acceptable. For others, a Bloom hit could trigger a precise lookup in Redis or PostgreSQL before rejecting.

That makes the revoked path slower, but keeps the normal non-revoked path fast.

### 5. Pipeline bulk revocation

Bulk revocation currently loops token by token. For high-volume revocation, use Redis pipelines or batched stream writes.

---

## Summary

HEX IAM's revocation system is designed to keep the normal request path local:

```text
read token JTI
check local Bloom filter
continue if not revoked
```

Redis Streams provide durable revocation replay. Redis Pub/Sub provides live fan-out. PostgreSQL `user_sessions` records provide session state and auditability.

The design is fast and pragmatic, but operators should understand the consistency model:

- live propagation is best-effort through Pub/Sub
- durable recovery comes from Stream replay
- Bloom filters can false-positive
- stream retention and reconciliation need production attention

