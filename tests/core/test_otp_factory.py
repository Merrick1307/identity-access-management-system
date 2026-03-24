import pytest

from app.core.otp_factory import OTPFactory, get_otp_manager


@pytest.mark.asyncio
async def test_otp_factory_singleton_and_roundtrip():
    manager1 = OTPFactory()
    manager2 = get_otp_manager()
    assert manager1 is manager2
    otp = await manager1.generate_otp(otp_validity=30, user_email='user@example.com', digits=6, tenant_id='tenant')
    assert await manager1.verify_otp(otp, 'user@example.com', 'tenant', otp_validity=30, digits=6) is True
