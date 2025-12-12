import base64
import hashlib
import hmac
import threading
from datetime import timedelta

import pyotp

from app.core.config import OTP_SECRET

DeprecationWarning("OTPFactory is deprecated, use OTPService instead")
class OTPFactory:
    __instance = None
    __lock = threading.Lock()

    def __new__(cls):
        if cls.__instance is None:
            with cls.__lock:
                if cls.__instance is None:
                    cls.__instance = super().__new__(cls)
                    cls.__instance.__master_secret = OTP_SECRET.encode("utf-8")
        return cls.__instance

    async def __derive_user_secret(self, email: str, tenant_id: str):
        data = f"{email}:{tenant_id}"
        hmac_obj = hmac.new(self.__master_secret, data.encode("utf8"), hashlib.sha256)
        digest = hmac_obj.digest()
        return base64.b32encode(digest).decode("utf-8")

    async def generate_otp(
            self, otp_validity: int, user_email: str,
            digits: int, tenant_id: str
    ) -> str:
        user_secret = await self.__derive_user_secret(user_email, tenant_id)

        totp = pyotp.TOTP(
            s=user_secret, digits=digits,
            interval=int(timedelta(seconds=otp_validity).total_seconds())
        )
        return totp.now()

    async def verify_otp(
            self, otp: str, user_email: str,
            tenant_id: str, otp_validity: int = 5,
            digits: int = 6
    ) -> bool:
        user_secret = await self.__derive_user_secret(user_email, tenant_id)
        totp = pyotp.TOTP(
            s=user_secret, digits=digits,
            interval=int(timedelta(seconds=otp_validity).total_seconds())
        )
        return totp.verify(otp)


def get_otp_manager():
    """Singleton instance of OTPManager"""
    return OTPFactory()
