"""
Tests for app/sso/oidc/services.py - OIDC service layer.
"""
import pytest
import base64
import hashlib
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock
import bcrypt

from app.sso.oidc.services import OIDCService


class TestValidateClient:
    """Tests for OIDCService.validate_client method."""
    
    @pytest.mark.asyncio
    async def test_validate_client_success_without_secret(self, mock_db_connection):
        """Test validating client without secret (public client)."""
        mock_client = {
            "id": "client-123",
            "name": "Test App",
            "redirect_uris": ["https://app.example.com/callback"],
            "is_active": True,
            "client_secret": None
        }
        mock_db_connection.fetchrow = AsyncMock(return_value=mock_client)
        
        result = await OIDCService.validate_client(
            db=mock_db_connection,
            client_id="client-123"
        )
        
        assert result is not None
        assert result["client_id"] == "client-123"
    
    @pytest.mark.asyncio
    async def test_validate_client_success_with_secret(self, mock_db_connection):
        """Test validating client with correct secret."""
        hashed_secret = bcrypt.hashpw(b"client-secret-123", bcrypt.gensalt()).decode()
        mock_client = {
            "id": "client-123",
            "name": "Confidential App",
            "client_secret": hashed_secret,
            "is_active": True
        }
        mock_db_connection.fetchrow = AsyncMock(return_value=mock_client)
        
        result = await OIDCService.validate_client(
            db=mock_db_connection,
            client_id="client-123",
            client_secret="client-secret-123"
        )
        
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_validate_client_wrong_secret(self, mock_db_connection):
        """Test validating client with wrong secret."""
        hashed_secret = bcrypt.hashpw(b"correct-secret", bcrypt.gensalt()).decode()
        mock_client = {
            "id": "client-123",
            "client_secret": hashed_secret,
            "is_active": True
        }
        mock_db_connection.fetchrow = AsyncMock(return_value=mock_client)
        
        result = await OIDCService.validate_client(
            db=mock_db_connection,
            client_id="client-123",
            client_secret="wrong-secret"
        )
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_validate_client_not_found(self, mock_db_connection):
        """Test validating non-existent client."""
        mock_db_connection.fetchrow = AsyncMock(return_value=None)
        
        result = await OIDCService.validate_client(
            db=mock_db_connection,
            client_id="nonexistent-client"
        )
        
        assert result is None


class TestValidateRedirectUri:
    """Tests for OIDCService.validate_redirect_uri method."""
    
    @pytest.mark.asyncio
    async def test_validate_redirect_uri_valid(self, mock_db_connection):
        """Test validating a registered redirect URI."""
        mock_db_connection.fetchval = AsyncMock(
            return_value=["https://app.example.com/callback", "https://app.example.com/auth"]
        )
        
        result = await OIDCService.validate_redirect_uri(
            db=mock_db_connection,
            client_id="client-123",
            redirect_uri="https://app.example.com/callback"
        )
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_validate_redirect_uri_not_registered(self, mock_db_connection):
        """Test validating an unregistered redirect URI."""
        mock_db_connection.fetchval = AsyncMock(
            return_value=["https://app.example.com/callback"]
        )
        
        result = await OIDCService.validate_redirect_uri(
            db=mock_db_connection,
            client_id="client-123",
            redirect_uri="https://malicious.com/callback"
        )
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_validate_redirect_uri_client_not_found(self, mock_db_connection):
        """Test validating redirect URI for non-existent client."""
        mock_db_connection.fetchval = AsyncMock(return_value=None)
        
        result = await OIDCService.validate_redirect_uri(
            db=mock_db_connection,
            client_id="nonexistent",
            redirect_uri="https://app.example.com/callback"
        )
        
        assert result is False


class TestGenerateAuthorizationCode:
    """Tests for OIDCService.generate_authorization_code method."""
    
    def test_generate_authorization_code_length(self):
        """Test that generated code has sufficient length."""
        code = OIDCService.generate_authorization_code()
        
        assert len(code) >= 32
    
    def test_generate_authorization_code_unique(self):
        """Test that generated codes are unique."""
        codes = [OIDCService.generate_authorization_code() for _ in range(100)]
        
        assert len(codes) == len(set(codes))
    
    def test_generate_authorization_code_url_safe(self):
        """Test that generated code is URL-safe."""
        code = OIDCService.generate_authorization_code()
        
        assert all(c.isalnum() or c in '-_' for c in code)


class TestStoreAuthorizationCode:
    """Tests for OIDCService.store_authorization_code method."""
    
    @pytest.mark.asyncio
    async def test_store_authorization_code(self, mock_db_connection):
        """Test storing an authorization code."""
        mock_db_connection.execute = AsyncMock()
        
        await OIDCService.store_authorization_code(
            db=mock_db_connection,
            code="auth-code-123",
            client_id="client-456",
            user_id="user-789",
            tenant_id="tenant-000",
            redirect_uri="https://app.example.com/callback",
            scope="openid profile email"
        )
        
        mock_db_connection.execute.assert_called_once()
        call_args = mock_db_connection.execute.call_args
        assert "INSERT INTO authorization_codes" in call_args[0][0]
    
    @pytest.mark.asyncio
    async def test_store_authorization_code_with_pkce(self, mock_db_connection):
        """Test storing authorization code with PKCE challenge."""
        mock_db_connection.execute = AsyncMock()
        
        await OIDCService.store_authorization_code(
            db=mock_db_connection,
            code="auth-code-123",
            client_id="client-456",
            user_id="user-789",
            tenant_id="tenant-000",
            redirect_uri="https://app.example.com/callback",
            scope="openid",
            code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            code_challenge_method="S256"
        )
        
        call_args = mock_db_connection.execute.call_args
        assert call_args[0][8] == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


class TestValidateAuthorizationCode:
    """Tests for OIDCService.validate_authorization_code method."""
    
    @pytest.mark.asyncio
    async def test_validate_authorization_code_success(self, mock_db_connection):
        """Test validating a valid authorization code."""
        mock_auth_code = {
            "id": "code-id",
            "code": "auth-code-123",
            "client_id": "client-456",
            "user_id": "user-789",
            "tenant_id": "tenant-000",
            "redirect_uri": "https://app.example.com/callback",
            "scope": "openid profile",
            "code_challenge": None,
            "code_challenge_method": None,
            "used": False,
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5)
        }
        mock_db_connection.fetchrow = AsyncMock(return_value=mock_auth_code)
        mock_db_connection.execute = AsyncMock()
        
        result = await OIDCService.validate_authorization_code(
            db=mock_db_connection,
            code="auth-code-123",
            client_id="client-456",
            redirect_uri="https://app.example.com/callback"
        )
        
        assert result is not None
        assert result["user_id"] == "user-789"
        mock_db_connection.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_validate_authorization_code_not_found(self, mock_db_connection):
        """Test validating non-existent code."""
        mock_db_connection.fetchrow = AsyncMock(return_value=None)
        
        result = await OIDCService.validate_authorization_code(
            db=mock_db_connection,
            code="nonexistent",
            client_id="client-456",
            redirect_uri="https://app.example.com/callback"
        )
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_validate_authorization_code_with_pkce_s256(self, mock_db_connection):
        """Test validating code with S256 PKCE challenge."""
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).decode().rstrip('=')
        
        mock_auth_code = {
            "id": "code-id",
            "code": "auth-code-123",
            "client_id": "client-456",
            "user_id": "user-789",
            "tenant_id": "tenant-000",
            "redirect_uri": "https://app.example.com/callback",
            "scope": "openid",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "used": False,
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5)
        }
        mock_db_connection.fetchrow = AsyncMock(return_value=mock_auth_code)
        mock_db_connection.execute = AsyncMock()
        
        result = await OIDCService.validate_authorization_code(
            db=mock_db_connection,
            code="auth-code-123",
            client_id="client-456",
            redirect_uri="https://app.example.com/callback",
            code_verifier=verifier
        )
        
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_validate_authorization_code_pkce_mismatch(self, mock_db_connection):
        """Test validating code with wrong PKCE verifier."""
        mock_auth_code = {
            "id": "code-id",
            "code": "auth-code-123",
            "client_id": "client-456",
            "user_id": "user-789",
            "tenant_id": "tenant-000",
            "redirect_uri": "https://app.example.com/callback",
            "scope": "openid",
            "code_challenge": "expected-challenge",
            "code_challenge_method": "S256",
            "used": False,
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5)
        }
        mock_db_connection.fetchrow = AsyncMock(return_value=mock_auth_code)
        
        result = await OIDCService.validate_authorization_code(
            db=mock_db_connection,
            code="auth-code-123",
            client_id="client-456",
            redirect_uri="https://app.example.com/callback",
            code_verifier="wrong-verifier"
        )
        
        assert result is None


class TestCreateIdToken:
    """Tests for OIDCService.create_id_token method."""
    
    @pytest.mark.asyncio
    async def test_create_id_token_basic(self):
        """Test creating a basic ID token."""
        token = await OIDCService.create_id_token(
            user_id="user-123",
            email="user@example.com",
            tenant_id="tenant-456",
            client_id="client-789"
        )
        
        assert token is not None
        assert isinstance(token, str)
    
    @pytest.mark.asyncio
    async def test_create_id_token_with_nonce(self):
        """Test creating ID token with nonce."""
        import jwt as pyjwt
        from app.core.config import JWT_SECRET
        
        token = await OIDCService.create_id_token(
            user_id="user-123",
            email="user@example.com",
            tenant_id="tenant-456",
            client_id="client-789",
            nonce="random-nonce-value"
        )
        
        decoded = pyjwt.decode(
            token, JWT_SECRET, algorithms=["HS256"],
            options={"verify_aud": False}
        )
        assert decoded["nonce"] == "random-nonce-value"
    
    @pytest.mark.asyncio
    async def test_create_id_token_with_user_info(self):
        """Test creating ID token with user info."""
        import jwt as pyjwt
        from app.core.config import JWT_SECRET
        
        token = await OIDCService.create_id_token(
            user_id="user-123",
            email="user@example.com",
            tenant_id="tenant-456",
            client_id="client-789",
            first_name="John",
            last_name="Doe",
            role="admin"
        )
        
        decoded = pyjwt.decode(
            token, JWT_SECRET, algorithms=["HS256"],
            options={"verify_aud": False}
        )
        assert decoded.get("given_name") == "John" or decoded.get("name", "").startswith("John")


class TestRefreshToken:
    """Tests for refresh token methods."""
    
    @pytest.mark.asyncio
    async def test_create_refresh_token(self, mock_db_connection):
        """Test creating a refresh token."""
        mock_db_connection.execute = AsyncMock()
        
        token = await OIDCService.create_refresh_token(
            db=mock_db_connection,
            user_id="user-123",
            tenant_id="tenant-456",
            client_id="client-789",
            scope="openid profile"
        )
        
        assert token is not None
        assert "user-123-refresh" in token
        mock_db_connection.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_validate_refresh_token_success(self, mock_db_connection):
        """Test validating a valid refresh token."""
        mock_token_data = {
            "jti": "user-123-refresh-abc123",
            "user_id": "user-123",
            "tenant_id": "tenant-456",
            "client_id": "client-789",
            "revoked": False,
            "expires_at": datetime.now(timezone.utc) + timedelta(days=7)
        }
        mock_db_connection.fetchrow = AsyncMock(return_value=mock_token_data)
        
        result = await OIDCService.validate_refresh_token(
            db=mock_db_connection,
            refresh_token="user-123-refresh-abc123",
            client_id="client-789"
        )
        
        assert result is not None
        assert result["user_id"] == "user-123"
    
    @pytest.mark.asyncio
    async def test_validate_refresh_token_revoked(self, mock_db_connection):
        """Test validating a revoked refresh token."""
        mock_db_connection.fetchrow = AsyncMock(return_value=None)
        
        result = await OIDCService.validate_refresh_token(
            db=mock_db_connection,
            refresh_token="revoked-token",
            client_id="client-789"
        )
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_revoke_refresh_token(self, mock_db_connection):
        """Test revoking a refresh token."""
        mock_db_connection.execute = AsyncMock()
        
        await OIDCService.revoke_refresh_token(
            db=mock_db_connection,
            refresh_token="token-to-revoke"
        )
        
        mock_db_connection.execute.assert_called_once()
        call_args = mock_db_connection.execute.call_args
        assert "UPDATE refresh_tokens SET revoked = TRUE" in call_args[0][0]
