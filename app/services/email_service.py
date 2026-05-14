from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Protocol

from fastapi_mail import FastMail, MessageSchema, MessageType
from pydantic import EmailStr, NameEmail
from fastapi.templating import Jinja2Templates

from app.core.config import ALGORITHM, APP_BASE_URL, APP_NAME, JWT_SECRET
from app.core.email_utils import configuration
from app.core.jwt_utils import create_jwt_token, create_purpose_token

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
EMAIL_TEMPLATES = Jinja2Templates(directory=str(TEMPLATES_DIR))


@dataclass(slots=True)
class EmailMessage:
    subject: str
    recipients: list[NameEmail]
    html_body: str


class EmailProvider(Protocol):
    async def send(self, message: EmailMessage) -> None: ...


class ApplicationEmailService(Protocol):
    def create_verification_token(self, *, user_id: str, tenant_id: str) -> str: ...

    async def send_verification_email(
        self,
        *,
        first_name: str,
        last_name: str,
        user_email: EmailStr | str,
        user_id: str,
        tenant_id: str,
        verification_token: Optional[str],
    ) -> None: ...

    async def send_invitation_email(
        self,
        *,
        recipient_email: str,
        recipient_name: str,
        inviter_name: str,
        organization_name: str,
        role: str,
        invitation_token: str,
        expires_at: datetime,
        client_name: Optional[str] = None,
    ) -> None: ...


class FastAPIMailProvider:
    async def send(self, message: EmailMessage) -> None:
        mailer = FastMail(config=configuration)
        schema = MessageSchema(
            subject=message.subject,
            recipients=message.recipients,
            body=message.html_body,
            subtype=MessageType.html,
        )
        await mailer.send_message(schema)


def _load_verification_template(first_name: str, verify_url: str) -> str:
    template_path = TEMPLATES_DIR / "onboarding" / "verification.html"
    template = template_path.read_text(encoding="utf-8")
    return template.format(
        app_name=APP_NAME,
        year=datetime.now().year,
        first_name=first_name,
        verify_url=verify_url,
    )


def _load_invitation_template(
    *,
    recipient_name: str,
    inviter_name: str,
    organization_name: str,
    role: str,
    accept_url: str,
    expires_at: str,
    client_name: Optional[str],
) -> str:
    return EMAIL_TEMPLATES.get_template("onboarding/invitation.html").render(
        recipient_name=recipient_name,
        inviter_name=inviter_name,
        organization_name=organization_name,
        role=role,
        accept_url=accept_url,
        expires_at=expires_at,
        client_name=client_name,
        app_name=APP_NAME,
        year=datetime.now().year,
    )


class TransactionalEmailService:
    def __init__(self, provider: EmailProvider) -> None:
        self._provider = provider

    async def send_verification_email(
        self,
        *,
        first_name: str,
        last_name: str,
        user_email: EmailStr | str,
        user_id: str,
        tenant_id: str,
        verification_token: Optional[str],
    ) -> None:
        payload = {
            "sub": str(user_email),
            "user_id": user_id,
            "tenant_id": tenant_id,
            "exp": datetime.now(timezone.utc) + timedelta(hours=24),
        }
        token = verification_token or create_jwt_token(payload=payload, secret_key=JWT_SECRET)
        verify_url = f"{APP_BASE_URL}/api/v1/onboarding/email/verify?token={token}"

        await self._provider.send(
            EmailMessage(
                subject=f"Verify your {APP_NAME} account",
                recipients=[NameEmail(name=f"{first_name} {last_name}", email=str(user_email))],
                html_body=_load_verification_template(first_name, verify_url),
            )
        )

    async def send_invitation_email(
        self,
        *,
        recipient_email: str,
        recipient_name: str,
        inviter_name: str,
        organization_name: str,
        role: str,
        invitation_token: str,
        expires_at: datetime,
        client_name: Optional[str] = None,
    ) -> None:
        base_url = APP_BASE_URL.rstrip("/")
        accept_url = f"{base_url}/api/v1/oidc/signup?invitation={invitation_token}"
        html = _load_invitation_template(
            recipient_name=recipient_name,
            inviter_name=inviter_name,
            organization_name=organization_name,
            role=role or "member",
            accept_url=accept_url,
            expires_at=expires_at.strftime("%Y-%m-%d %H:%M UTC"),
            client_name=client_name,
        )
        await self._provider.send(
            EmailMessage(
                subject=f"Invitation to join {organization_name} on {APP_NAME}",
                recipients=[NameEmail(name=recipient_name, email=recipient_email)],
                html_body=html,
            )
        )

    def create_verification_token(self, *, user_id: str, tenant_id: str) -> str:
        verification_payload = {
            "user_id": user_id,
            "tenant_id": tenant_id,
            "purpose": "email_verify",
            "exp": datetime.now(timezone.utc) + timedelta(hours=24),
            "iat": datetime.now(timezone.utc),
        }
        return create_purpose_token(verification_payload, JWT_SECRET, ALGORITHM or "HS256")


_default_email_service: ApplicationEmailService = TransactionalEmailService(FastAPIMailProvider())


def get_email_service() -> ApplicationEmailService:
    return _default_email_service
