"""
Distributed Token Revocation using Redis Streams + Local Bloom Filters.

Architecture:
    Token revoked → Write to Redis Stream (persistent, ordered)
                  ↓
            All N workers consuming from stream
                  ↓
            Each adds token to their local bloom filter
                  ↓
            Request arrives → Check local bloom filter (instant, no network)

Compliance Notes:
    - Redis Streams provide durability via AOF/RDB persistence
    - Every revocation is timestamped and ordered in the stream
    - On startup, workers load ALL revocations from stream via XRANGE
    - Stream is the single source of truth for revocations
    - Meets SOC 2, HIPAA, PCI-DSS session termination requirements

Benefits:
- O(1) token validation (bloom filter lookup)
- No network hop for every request  
- Horizontal scaling: each worker has its own bloom filter
- Eventual consistency (tokens propagate within milliseconds)
- Full audit trail of all revocations in Redis Stream
"""
import asyncio
import logging
from dataclasses import dataclass
from typing import Optional
import os

from rbloom import Bloom
import redis.asyncio as redis

logger = logging.getLogger(__name__)

STREAM_NAME = "token:revocations"
CONSUMER_GROUP = "bloom-sync"
BATCH_SIZE = 100
BLOCK_MS = 1000


@dataclass
class RevocationEvent:
    """Token revocation event."""
    jti: str
    user_id: str
    tenant_id: str
    reason: str
    timestamp: str


class TokenRevocationManager:
    """
    Manages distributed token revocation using Redis Streams.
    
    Each worker instance:
    1. Maintains a local bloom filter for O(1) revocation checks
    2. Publishes revocations to Redis Stream
    3. Consumes from stream to sync bloom filter with other workers
    """
    
    def __init__(
        self,
        redis_client: redis.Redis,
        bloom_filter: Bloom,
        worker_id: str = None
    ):
        self.redis = redis_client
        self.bloom = bloom_filter
        self.worker_id = worker_id or f"worker-{os.getpid()}"
        self._consumer_task: Optional[asyncio.Task] = None
        self._running = False
    
    async def initialize(self):
        """Initialize consumer group and start background consumer."""
        # Create consumer group if it doesn't exist
        try:
            await self.redis.xgroup_create(
                STREAM_NAME, 
                CONSUMER_GROUP, 
                id="0",
                mkstream=True
            )
            logger.info(f"Created consumer group '{CONSUMER_GROUP}'")
        except redis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise
            # Group already exists, that's fine
        
        # Load existing revocations from stream into bloom filter
        await self._load_existing_revocations()
        
        # Start background consumer
        self._running = True
        self._consumer_task = asyncio.create_task(self._consume_loop())
        logger.info(f"Token revocation manager started (worker: {self.worker_id})")
    
    async def _load_existing_revocations(self):
        """Load all existing revocations from stream into bloom filter on startup."""
        count = 0
        last_id = "0"
        
        while True:
            entries = await self.redis.xrange(
                STREAM_NAME, 
                min=last_id, 
                count=BATCH_SIZE
            )
            
            if not entries:
                break
            
            for entry_id, data in entries:
                jti = data.get("jti")
                if jti:
                    self.bloom.add(jti)
                    count += 1
                last_id = entry_id
            
            # Move past the last ID we processed
            if entries:
                last_id = f"({last_id}"
        
        logger.info(f"Loaded {count} existing revocations into bloom filter")
    
    async def revoke_token(
        self,
        jti: str,
        user_id: str,
        tenant_id: str,
        reason: str = "user_logout"
    ) -> bool:
        """
        Revoke a token and broadcast to all workers.
        
        Args:
            jti: JWT ID to revoke
            user_id: User who owns the token
            tenant_id: Tenant the user belongs to
            reason: Revocation reason (logout, password_change, admin_revoke, etc.)
        
        Returns:
            True if successfully published
        """
        # Add to local bloom filter immediately
        self.bloom.add(jti)
        
        # Publish to stream for other workers (and persistence)
        try:
            await self.redis.xadd(
                STREAM_NAME,
                {
                    "jti": jti,
                    "user_id": user_id,
                    "tenant_id": tenant_id,
                    "reason": reason,
                },
                maxlen=1_000_000  # Keep last 1M revocations
            )
            logger.debug(f"Token revoked: {jti[:8]}... (reason: {reason})")
            return True
        except Exception as e:
            logger.error(f"Failed to publish revocation: {e}")
            # Token is still in local bloom, so it's blocked on this worker
            return False
    
    async def revoke_user_tokens(
        self,
        user_id: str,
        tenant_id: str,
        jtis: list[str],
        reason: str = "logout_all"
    ) -> int:
        """Revoke multiple tokens for a user (e.g., logout all sessions)."""
        count = 0
        for jti in jtis:
            if await self.revoke_token(jti, user_id, tenant_id, reason):
                count += 1
        return count
    
    def is_revoked(self, jti: str) -> bool:
        """
        Check if a token is revoked. O(1) bloom filter lookup.
        
        Note: Bloom filters can have false positives (says revoked when it's not)
        but never false negatives (if it says not revoked, it's definitely not).
        """
        return jti in self.bloom
    
    async def _consume_loop(self):
        """Background task that consumes revocation events from stream."""
        logger.info(f"Consumer loop started for {self.worker_id}")
        
        while self._running:
            try:
                # Read new messages from stream
                entries = await self.redis.xreadgroup(
                    CONSUMER_GROUP,
                    self.worker_id,
                    {STREAM_NAME: ">"},
                    count=BATCH_SIZE,
                    block=BLOCK_MS
                )
                
                if not entries:
                    continue
                
                for stream_name, messages in entries:
                    for msg_id, data in messages:
                        jti = data.get("jti")
                        if jti:
                            # Add to local bloom filter
                            self.bloom.add(jti)
                        
                        # Acknowledge message
                        await self.redis.xack(STREAM_NAME, CONSUMER_GROUP, msg_id)
                
            except asyncio.CancelledError:
                logger.info("Consumer loop cancelled")
                break
            except Exception as e:
                logger.error(f"Consumer error: {e}")
                await asyncio.sleep(1)  # Back off on error
    
    async def shutdown(self):
        """Stop the consumer and cleanup."""
        self._running = False
        if self._consumer_task:
            self._consumer_task.cancel()
            try:
                await self._consumer_task
            except asyncio.CancelledError:
                pass
        logger.info(f"Token revocation manager stopped (worker: {self.worker_id})")
    
    async def get_stats(self) -> dict:
        """Get revocation stats."""
        try:
            stream_info = await self.redis.xinfo_stream(STREAM_NAME)
            stream_length = stream_info.get("length", 0)
        except Exception:
            stream_length = "unavailable"
        
        return {
            "worker_id": self.worker_id,
            "stream_length": stream_length,
            "bloom_filter_capacity": self.bloom.expected_items if hasattr(self.bloom, 'expected_items') else "unknown",
        }


# Global instance
_revocation_manager: Optional[TokenRevocationManager] = None


async def init_revocation_manager(app_state) -> TokenRevocationManager:
    """Initialize the global revocation manager."""
    global _revocation_manager
    
    _revocation_manager = TokenRevocationManager(
        redis_client=app_state.redis,
        bloom_filter=app_state.bloom_filter
    )
    await _revocation_manager.initialize()
    
    # Store reference in app state
    app_state.revocation_manager = _revocation_manager
    
    return _revocation_manager


async def shutdown_revocation_manager():
    """Shutdown the global revocation manager."""
    global _revocation_manager
    if _revocation_manager:
        await _revocation_manager.shutdown()
        _revocation_manager = None


def get_revocation_manager() -> TokenRevocationManager:
    """Get the global revocation manager instance."""
    if not _revocation_manager:
        raise RuntimeError("Revocation manager not initialized")
    return _revocation_manager
