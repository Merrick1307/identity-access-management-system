from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException

from app.services.otp_service import OTPService


@pytest.fixture
def otp_service():
    return OTPService(Fernet.generate_key().decode())


def test_private_crypto_helpers(otp_service):
    encrypted = otp_service._OTPService__encrypt_otp_secret('secret')
    assert encrypted != 'secret'
    assert otp_service._OTPService__decrypt_otp_secret(encrypted) == 'secret'
    assert len(otp_service._OTPService__generate_backup_codes(3)) == 3


@pytest.mark.asyncio
async def test_provision_stateless_otp_branches(otp_service, mock_db_connection):
    # MFA disabled
    mock_db_connection.fetchval = AsyncMock(return_value=False)
    with pytest.raises(HTTPException):
        await otp_service.provision_stateless_otp('u@example.com', 'aud', 'tenant', mock_db_connection)

    mock_db_connection.fetchval = AsyncMock(side_effect=[True, None])
    with pytest.raises(HTTPException):
        await otp_service.provision_stateless_otp('u@example.com', 'aud', 'tenant', mock_db_connection)

    mock_db_connection.fetchval = AsyncMock(side_effect=[True, 'HexShare', 'existing-secret'])
    with pytest.raises(HTTPException):
        await otp_service.provision_stateless_otp('u@example.com', 'aud', 'tenant', mock_db_connection)

    mock_db_connection.fetchval = AsyncMock(side_effect=[True, 'HexShare', None])
    mock_db_connection.execute = AsyncMock(return_value='INSERT 0 1')
    result = await otp_service.provision_stateless_otp('u@example.com', 'aud', 'tenant', mock_db_connection)
    assert result.uri.startswith('otpauth://totp/')
    assert len(result.backup_codes) == 12


@pytest.mark.asyncio
async def test_verify_otp_branches(otp_service, mock_db_connection):
    mock_db_connection.fetchval = AsyncMock(return_value=None)
    with pytest.raises(HTTPException):
        await otp_service.verify_otp('aud', 'u@example.com', mock_db_connection, '12345678', 'tenant')

    mock_db_connection.fetchval = AsyncMock(return_value='HexShare')
    mock_db_connection.fetchrow = AsyncMock(return_value={'otp_secret': None, 'is_replayed': False})
    with pytest.raises(HTTPException):
        await otp_service.verify_otp('aud', 'u@example.com', mock_db_connection, '12345678', 'tenant')

    encrypted = otp_service._OTPService__encrypt_otp_secret('A'*32)
    mock_db_connection.fetchrow = AsyncMock(return_value={'otp_secret': encrypted, 'is_replayed': True})
    with pytest.raises(HTTPException):
        await otp_service.verify_otp('aud', 'u@example.com', mock_db_connection, '12345678', 'tenant')

    import pyotp
    secret = pyotp.random_base32()
    encrypted = otp_service._OTPService__encrypt_otp_secret(secret)
    code = pyotp.TOTP(secret, digits=8, interval=otp_service.OTP_INTERVAL).now()
    mock_db_connection.fetchrow = AsyncMock(return_value={'otp_secret': encrypted, 'is_replayed': False})
    mock_db_connection.execute = AsyncMock()
    assert await otp_service.verify_otp('aud', 'u@example.com', mock_db_connection, code, 'tenant') is True
    assert mock_db_connection.execute.await_count == 1

    wrong = '00000000'
    mock_db_connection.fetchrow = AsyncMock(return_value={'otp_secret': encrypted, 'is_replayed': False})
    assert await otp_service.verify_otp('aud', 'u@example.com', mock_db_connection, wrong, 'tenant') is False
