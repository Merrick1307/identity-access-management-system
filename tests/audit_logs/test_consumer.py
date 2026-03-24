import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import redis.asyncio as redis

from app.audit_logs.consumer import AuditLogConsumer, get_db_url, STREAM_NAME, CONSUMER_GROUP


def test_get_db_url_contains_encoded_password(monkeypatch):
    monkeypatch.setattr('app.audit_logs.consumer.DATABASE_URL', 'localhost:5432/db')
    monkeypatch.setattr('app.audit_logs.consumer.DATABASE_USER', 'user')
    monkeypatch.setattr('app.audit_logs.consumer.DATABASE_PASSWORD', 'pa ss')
    assert 'pa+ss' in get_db_url()


@pytest.mark.asyncio
async def test_consumer_connect_process_batch_run_and_close():
    fake_redis = AsyncMock()
    fake_pool = MagicMock()
    fake_pool.close = AsyncMock()
    fake_conn_cm = AsyncMock()
    fake_conn = AsyncMock()
    fake_conn_cm.__aenter__.return_value = fake_conn
    fake_pool.acquire.return_value = fake_conn_cm
    with patch('app.audit_logs.consumer.redis.from_url', return_value=fake_redis), \
         patch('app.audit_logs.consumer.asyncpg.create_pool', new=AsyncMock(return_value=fake_pool)):
        consumer = AuditLogConsumer()
        await consumer.connect()
    fake_redis.xgroup_create.assert_awaited()

    messages = [('1-0', {'timestamp': '2024-01-01T00:00:00', 'level': 'INFO', 'logger': 'audit', 'message': 'hello', 'module': 'None', 'function': 'None', 'line': 'None', 'thread_id': 'None', 'process_id': 'None', 'extra': 'null'})]
    await consumer.process_batch(messages)
    fake_conn.executemany.assert_awaited()
    fake_redis.xack.assert_awaited_with(STREAM_NAME, CONSUMER_GROUP, '1-0')

    consumer.running = True
    fake_redis.xreadgroup = AsyncMock(side_effect=[[(STREAM_NAME, messages)], asyncio.CancelledError()])
    # patch process_batch to stop after one call
    consumer.process_batch = AsyncMock(side_effect=lambda msgs: setattr(consumer, 'running', False))
    await consumer.run()
    consumer.process_batch.assert_awaited()

    consumer.stop()
    assert consumer.running is False
    await consumer.close()
    fake_redis.close.assert_awaited()
    fake_pool.close.assert_awaited()


@pytest.mark.asyncio
async def test_consumer_connect_busygroup_and_run_error(monkeypatch):
    fake_redis = AsyncMock()
    fake_redis.xgroup_create = AsyncMock(side_effect=redis.ResponseError('BUSYGROUP exists'))
    fake_pool = AsyncMock()
    with patch('app.audit_logs.consumer.redis.from_url', return_value=fake_redis), \
         patch('app.audit_logs.consumer.asyncpg.create_pool', new=AsyncMock(return_value=fake_pool)):
        consumer = AuditLogConsumer()
        await consumer.connect()

    fake_redis.xreadgroup = AsyncMock(side_effect=[Exception('boom'), asyncio.CancelledError()])
    with patch('app.audit_logs.consumer.asyncio.sleep', new=AsyncMock()):
        await consumer.run()
