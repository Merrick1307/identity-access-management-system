"""
Redis Streams Consumer for Audit Logs

Reads from Redis Stream and writes to PostgreSQL in batches.
Run as a separate worker process:
    python -m app.audit_logs.consumer
"""
import asyncio
import json
import os
import signal
from datetime import datetime

import asyncpg
import redis.asyncio as redis

# Configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
DATABASE_URL = os.getenv("DATABASE_URL", "localhost:5432/hexiam")
DATABASE_USER = os.getenv("DATABASE_USER", "postgres")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD", "postgres")

STREAM_NAME = "audit_logs"
CONSUMER_GROUP = "audit_log_writers"
CONSUMER_NAME = f"consumer-{os.getpid()}"
BATCH_SIZE = 100
BLOCK_MS = 5000  # 5 seconds


class AuditLogConsumer:
    """Consumes audit logs from Redis Stream and writes to PostgreSQL."""
    
    def __init__(self):
        self.redis: redis.Redis = None
        self.db_pool: asyncpg.Pool = None
        self.running = True
    
    async def connect(self):
        """Initialize Redis and PostgreSQL connections."""
        # Redis
        self.redis = redis.from_url(
            REDIS_URL,
            encoding="utf-8",
            decode_responses=True
        )
        
        # PostgreSQL
        db_url = f"postgres://{DATABASE_USER}:{DATABASE_PASSWORD}@{DATABASE_URL}"
        self.db_pool = await asyncpg.create_pool(
            db_url,
            min_size=2,
            max_size=10
        )
        
        # Create consumer group (if not exists)
        try:
            await self.redis.xgroup_create(
                STREAM_NAME, 
                CONSUMER_GROUP, 
                id="0",
                mkstream=True
            )
            print(f"Created consumer group: {CONSUMER_GROUP}")
        except redis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise
            print(f"Consumer group {CONSUMER_GROUP} already exists")
    
    async def close(self):
        """Clean up connections."""
        if self.redis:
            await self.redis.close()
        if self.db_pool:
            await self.db_pool.close()
    
    async def process_batch(self, messages: list):
        """Write a batch of log entries to PostgreSQL."""
        if not messages:
            return
        
        records = []
        message_ids = []
        
        for msg_id, fields in messages:
            message_ids.append(msg_id)
            
            # Parse timestamp
            timestamp_str = fields.get("timestamp", datetime.utcnow().isoformat())
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.utcnow()
            
            # Build record tuple
            records.append((
                timestamp,
                fields.get("level", "INFO"),
                fields.get("logger", "audit"),
                fields.get("message", ""),
                fields.get("module"),
                fields.get("function"),
                int(fields.get("line", 0)) if fields.get("line") else None,
                int(fields.get("thread_id", 0)) if fields.get("thread_id") else None,
                int(fields.get("process_id", 0)) if fields.get("process_id") else None,
                fields.get("extra")
            ))
        
        # Batch insert to PostgreSQL
        async with self.db_pool.acquire() as conn:
            await conn.executemany(
                """
                INSERT INTO audit_logs 
                (timestamp, level, logger_name, message, module, function, 
                 line_number, thread_id, process_id, extra_data)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                """,
                records
            )
        
        # Acknowledge messages
        if message_ids:
            await self.redis.xack(STREAM_NAME, CONSUMER_GROUP, *message_ids)
        
        print(f"Processed {len(records)} log entries")
    
    async def run(self):
        """Main consumer loop."""
        print(f"Starting consumer: {CONSUMER_NAME}")
        print(f"Reading from stream: {STREAM_NAME}")
        print(f"Consumer group: {CONSUMER_GROUP}")
        
        while self.running:
            try:
                # Read from stream (blocking)
                messages = await self.redis.xreadgroup(
                    CONSUMER_GROUP,
                    CONSUMER_NAME,
                    {STREAM_NAME: ">"},  # ">" = only new messages
                    count=BATCH_SIZE,
                    block=BLOCK_MS
                )
                
                if messages:
                    # messages = [(stream_name, [(id, fields), ...])]
                    for stream_name, stream_messages in messages:
                        await self.process_batch(stream_messages)
                
            except asyncio.CancelledError:
                print("Consumer cancelled, shutting down...")
                break
            except Exception as e:
                print(f"Error processing messages: {e}")
                await asyncio.sleep(1)  # Back off on error
        
        print("Consumer stopped")
    
    def stop(self):
        """Signal the consumer to stop."""
        self.running = False


async def main():
    consumer = AuditLogConsumer()
    
    # Handle shutdown signals
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, consumer.stop)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass
    
    try:
        await consumer.connect()
        await consumer.run()
    finally:
        await consumer.close()


if __name__ == "__main__":
    asyncio.run(main())
