from unittest.mock import AsyncMock, patch

import pytest

from app.api.v1.otp import register_otp, verify_otp
from app.core.jwt_utils import VerifiedTokenData


def current_user():
    return VerifiedTokenData(email='user@example.com', tenant_id='tenant', policy={}, role='user', user_id='u1', exp=None, iat=None, aud='client')


@pytest.mark.asyncio
async def test_register_otp_route(mock_db_connection):
    fake_response = {'otp_secret': 'ABC', 'uri': 'otpauth://', 'backup_codes': ['X']}
    with patch('app.api.v1.otp.OTPService.provision_stateless_otp', new=AsyncMock(return_value=fake_response)):
        resp = await register_otp(current_user(), mock_db_connection)
    body = json_body(resp)
    assert body['message'] == 'OTP provisioned successfully'
    assert body['data'] == fake_response


@pytest.mark.asyncio
async def test_verify_otp_route(mock_db_connection):
    with patch('app.api.v1.otp.OTPService.verify_otp', new=AsyncMock(return_value=True)):
        resp = await verify_otp('12345678', current_user(), mock_db_connection)
    body = json_body(resp)
    assert body['data']['verified'] is True


def json_body(response):
    import json
    return json.loads(response.body)
