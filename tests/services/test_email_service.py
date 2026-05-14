from datetime import datetime
from unittest.mock import AsyncMock

import jwt
import pytest

from app.core.config import JWT_SECRET
from app.services.email_service import TransactionalEmailService


@pytest.mark.asyncio
async def test_send_verification_email_uses_provider():
    provider = AsyncMock()
    service = TransactionalEmailService(provider)

    await service.send_verification_email(
        first_name="Jane",
        last_name="Doe",
        user_email="jane@example.com",
        user_id="user-1",
        tenant_id="tenant-1",
        verification_token="token-123",
    )

    provider.send.assert_awaited_once()
    message = provider.send.await_args.args[0]
    assert message.subject.startswith("Verify your")
    assert message.recipients[0].email == "jane@example.com"
    assert "token-123" in message.html_body


@pytest.mark.asyncio
async def test_send_invitation_email_uses_provider():
    provider = AsyncMock()
    service = TransactionalEmailService(provider)

    await service.send_invitation_email(
        recipient_email="invitee@example.com",
        recipient_name="invitee@example.com",
        inviter_name="admin@example.com",
        organization_name="Acme",
        role="member",
        invitation_token="invite-token",
        expires_at=datetime(2026, 5, 14, 12, 0),
        client_name="HexShare",
    )

    provider.send.assert_awaited_once()
    message = provider.send.await_args.args[0]
    assert message.subject.startswith("Invitation to join Acme")
    assert message.recipients[0].email == "invitee@example.com"
    assert "invite-token" in message.html_body


def test_create_verification_token_encodes_expected_claims():
    provider = AsyncMock()
    service = TransactionalEmailService(provider)

    token = service.create_verification_token(user_id="user-1", tenant_id="tenant-1")
    payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])

    assert payload["purpose"] == "email_verify"
    assert payload["user_id"] == "user-1"
    assert payload["tenant_id"] == "tenant-1"
