import secrets
from datetime import datetime, timezone

import pyotp
from asyncpg import Connection
from cryptography.fernet import Fernet
from fastapi import HTTPException

from app.models.responses import OTPProvisionResponse


class OTPService:
    OTP_INTERVAL: int = 45
    def __init__(self, encrypt_key: str):
        self.cipher = Fernet(encrypt_key.encode())

    def __generate_stateless_otp(self, user_secret: str, user_email: str, issuer: str):
        totp = pyotp.TOTP(
            s=user_secret, name=user_email, issuer=issuer,
            digits=8, interval=self.OTP_INTERVAL
        )

        # Generate current OTP code (changes every 45 seconds)
        current_code = totp.now()

        return current_code

    def __generate_backup_codes(self, count: int = 12) -> list[str]:
        """Generate backup recovery codes"""
        return [secrets.token_hex(4).upper() for _ in range(count)]

    def __encrypt_otp_secret(self, otp_secret: str):
        try:
            encrypted_key = self.cipher.encrypt(otp_secret.encode())
            return encrypted_key.decode()
        except Exception as e:
            raise e


    def __decrypt_otp_secret(self, encrypted_otp_secret: str):
        try:
            key_to_decrypt: bytes = encrypted_otp_secret.encode('utf-8')
            decrypted_key = self.cipher.decrypt(key_to_decrypt)
            return decrypted_key.decode()
        except Exception as e:
            raise e


    async def provision_stateless_otp(self, user_email: str, aud: str, tenant_id: str, db: Connection):
        mfa_enabled = await self.__verify_mfa_enabled_for_tenant(tenant_id, db)
        if not mfa_enabled:
            raise HTTPException(
                status_code=403,
                detail="MFA is not enabled for this tenant"
            )

        issuer = await db.fetchval(
            """
            SELECT name FROM oidc_clients 
            WHERE id = $1 AND tenant_id = $2 AND is_active = TRUE
            """,
            aud, tenant_id
        )
        if not issuer:
            raise HTTPException(
                status_code=404,
                detail="Client application not found"
            )

        existing = await db.fetchval(
            """
            SELECT otp_secret FROM totp_secrets
            WHERE tenant_id = $1 AND user_email = $2 AND issuer = $3 AND is_active = TRUE
            """,
            tenant_id, user_email, issuer
        )

        if existing:
            raise HTTPException(
                status_code=409,
                detail="OTP already provisioned for this user"
            )
        otp = pyotp.random_base32()
        # # Then create a TOTP object for verification
        otp_secret = self.__encrypt_otp_secret(otp)
        backup_codes = self.__generate_backup_codes()

        # Hash backup codes before storing
        hashed_backups = [
            self.cipher.encrypt(code.encode()).decode()
            for code in backup_codes
        ]
        inserted: str = await db.execute(
            """
            INSERT INTO otp_secrets (tenant_id, user_email, issuer, otp_secret, backup_codes)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING otp_secret
            """,
            tenant_id, user_email, issuer, otp_secret, hashed_backups
        )
        if inserted == "INSERT 0 0":
            raise HTTPException(
                status_code=500,
                detail="Error occurred while generating secret key, please try again later"
            )
        totp = pyotp.TOTP(
            s=otp, name=user_email, issuer=issuer,
            digits=8, interval=self.OTP_INTERVAL
        )
        # Generate a provisioning URI for QR code
        uri = totp.provisioning_uri(name=user_email, issuer_name=issuer)

        return OTPProvisionResponse(
            otp_secret=otp,
            uri=uri,
            backup_codes=backup_codes
        )


    async def verify_otp(
            self, aud: str, user_email: str, db: Connection,
            otp_code: str, tenant_id: str
    ) -> bool:
        issuer = await db.fetchval(
            """
            SELECT name FROM oidc_clients 
            WHERE id = $1 AND tenant_id = $2 AND is_active = TRUE
            """,
            aud, tenant_id
        )
        if not issuer:
            raise HTTPException(
                status_code=404,
                detail="Client application not found"
            )
        row = await db.fetchrow(
            """
            SELECT 
                otp_secret, 
                updated_at,
                CASE 
                    WHEN updated_at IS NOT NULL 
                         AND EXTRACT(EPOCH FROM ($3 - last_used_at)) < 45
                    THEN true 
                    ELSE false 
                END as is_replayed
            FROM otp_secrets
            WHERE user_email = $1 
              AND issuer = $2 
              AND is_active = TRUE
            """,
            user_email, issuer, datetime.now(timezone.utc)
        )
        if not row["otp_secret"]:
            raise HTTPException(
                status_code=404,
                detail="OTP secret not found for the given user and issuer"
            )
        if row["is_replayed"]:
            raise HTTPException(
                status_code=403,
                detail="OTP used"
            )

        decrypted_secret = self.__decrypt_otp_secret(row["otp_secret"])
        totp = pyotp.TOTP(
            s=decrypted_secret,
            name=user_email,
            issuer=issuer,
            digits=8,
            interval=self.OTP_INTERVAL
        )

        is_valid = totp.verify(otp_code, valid_window=1)  # Allows ±1 interval

        if is_valid:
            await db.execute(
                "UPDATE otp_secrets SET updated_at = $1 WHERE user_email = $2 AND issuer = $3",
                datetime.now(timezone.utc), user_email, issuer
            )
            return True
        return False

    async def __verify_mfa_enabled_for_tenant(self, tenant_id: str, db: Connection) -> bool:
        return await db.fetchval(
            """
                SELECT COALESCE((settings->'mfa_enabled')::boolean, false)
                FROM tenants 
                WHERE id = $1 AND is_active = TRUE
            """,
            tenant_id
        ) or False
