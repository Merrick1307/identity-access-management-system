from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import orjson
import pytest
from fastapi import BackgroundTasks
from starlette.requests import Request

from app.core.jwt_utils import VerifiedTokenData
from app.sso.oidc import signup as routes


def make_request(path: str = "/api/v1/oidc/signup") -> Request:
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": [],
        "query_string": b"",
        "scheme": "https",
        "server": ("hexiam.test", 443),
        "client": ("127.0.0.1", 1234),
        "app": SimpleNamespace(state=SimpleNamespace()),
    }
    return Request(scope)


@pytest.mark.asyncio
async def test_signup_submit_schedules_verification_email(mock_db_connection, mock_audit_logger):
    background_tasks = BackgroundTasks()
    request = make_request()
    email_service = SimpleNamespace(
        send_verification_email=AsyncMock(),
        send_invitation_email=AsyncMock(),
        create_verification_token=MagicMock(return_value="verification-token"),
    )

    mock_db_connection.fetchrow = AsyncMock(return_value=None)
    mock_db_connection.execute = AsyncMock()

    with patch.object(routes.OIDCService, "validate_client", new=AsyncMock(return_value={"name": "HexShare", "tenant_id": "tenant-1"})), \
         patch.object(routes, "get_email_service", return_value=email_service):
        response = await routes.signup_submit(
            request=request,
            background_tasks=background_tasks,
            email="user@example.com",
            password="Password123!",
            confirm_password="Password123!",
            first_name="Test",
            last_name="User",
            client_id="client-1",
            redirect_uri="https://app.example.com/callback",
            invitation_token="",
            db=mock_db_connection,
            logger=mock_audit_logger,
        )

    assert response.status_code == 200
    assert len(background_tasks.tasks) == 1
    assert background_tasks.tasks[0].func is email_service.send_verification_email


@pytest.mark.asyncio
async def test_signup_api_schedules_verification_email(mock_db_connection, mock_audit_logger):
    background_tasks = BackgroundTasks()
    email_service = SimpleNamespace(
        send_verification_email=AsyncMock(),
        send_invitation_email=AsyncMock(),
        create_verification_token=MagicMock(return_value="verification-token"),
    )
    request_data = routes.SignupRequest(
        email="user@example.com",
        password="Password123!",
        first_name="Test",
        last_name="User",
    )

    mock_db_connection.fetchrow = AsyncMock(return_value=None)
    mock_db_connection.execute = AsyncMock()

    with patch.object(routes.OIDCService, "validate_client", new=AsyncMock(return_value={"tenant_id": "tenant-1"})), \
         patch.object(routes, "get_email_service", return_value=email_service), \
         patch.object(routes, "create_verification_token", return_value="test-token") as mock_create_token:
        response = await routes.signup_api(
            request=request_data,
            background_tasks=background_tasks,
            client_id="client-1",
            db=mock_db_connection,
            logger=mock_audit_logger,
        )

    assert response.status_code == 201
    assert mock_create_token.called
    assert len(background_tasks.tasks) == 1
    assert background_tasks.tasks[0].func is email_service.send_verification_email
    body = orjson.loads(response.body)
    assert body["data"]["verification_email_sent"] is True
    assert "verification_token" not in body["data"]


@pytest.mark.asyncio
async def test_create_invitation_schedules_email(mock_db_connection, mock_audit_logger):
    background_tasks = BackgroundTasks()
    email_service = SimpleNamespace(
        send_verification_email=AsyncMock(),
        send_invitation_email=AsyncMock(),
    )
    auth = VerifiedTokenData(
        email="admin@example.com",
        tenant_id="tenant-1",
        policy={},
        role="admin",
        user_id="admin-1",
        exp=None,
        iat=None,
        aud="client-1",
    )
    invitation = routes.InvitationRequest(
        email="invitee@example.com",
        role="member",
        client_id="client-1",
    )

    mock_db_connection.fetchrow = AsyncMock(
        side_effect=[
            None,
            None,
            {"name": "Acme"},
        ]
    )
    mock_db_connection.execute = AsyncMock()

    with patch.object(routes.OIDCService, "validate_client", new=AsyncMock(return_value={"name": "HexShare"})), \
         patch.object(routes, "get_email_service", return_value=email_service), \
         patch.object(routes, "create_purpose_token", return_value="invitation-token"):
        response = await routes.create_invitation(
            invitation=invitation,
            background_tasks=background_tasks,
            auth=auth,
            db=mock_db_connection,
            logger=mock_audit_logger,
        )

    assert response.status_code == 201
    assert len(background_tasks.tasks) == 1
    assert background_tasks.tasks[0].func is email_service.send_invitation_email
