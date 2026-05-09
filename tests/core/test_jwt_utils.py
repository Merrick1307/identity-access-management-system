"""
Tests for app/core/jwt_utils.py - JWT utilities.
"""
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

import jwt as pyjwt
import pytest

from app.core.jwt_utils import (
    create_jwt_token,
    create_purpose_token,
    decode_purpose_token,
    VerifyToken,
    VerifiedTokenData,
    extract_token,
)
from app.core.config import JWT_SECRET


class TestCreateJwtToken:
    """Tests for create_jwt_token function."""
    
    @pytest.mark.asyncio
    async def test_create_jwt_token_with_user_id(self):
        """Test creating JWT token with user_id in payload."""
        payload = {
            "sub": "user@example.com",
            "user_id": "user-123",
            "tenant_id": "tenant-456",
            "role": "admin",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1)
        }
        
        token = create_jwt_token(payload, JWT_SECRET)
        
        assert token is not None
        decoded = pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        assert decoded["sub"] == "user@example.com"
        assert decoded["user_id"] == "user-123"
    
    @pytest.mark.asyncio
    async def test_create_jwt_token_has_jti_header(self):
        """Test that created token has JTI in header."""
        payload = {
            "sub": "user@example.com",
            "user_id": "user-123",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1)
        }
        
        token = create_jwt_token(payload, JWT_SECRET)
        
        headers = pyjwt.get_unverified_header(token)
        assert "jti" in headers
        assert headers["jti"].startswith("user-123-")
    
    @pytest.mark.asyncio
    async def test_create_jwt_token_uses_sub_when_no_user_id(self):
        """Test JTI uses sub when user_id not provided."""
        payload = {
            "sub": "user@example.com",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1)
        }
        
        token = create_jwt_token(payload, JWT_SECRET)
        
        headers = pyjwt.get_unverified_header(token)
        assert headers["jti"].startswith("user@example.com-")


class TestCreatePurposeToken:
    """Tests for create_purpose_token function."""
    
    def test_create_purpose_token(self):
        """Test creating a purpose token."""
        payload = {
            "purpose": "email_verification",
            "user_id": "user-123",
            "exp": datetime.now(timezone.utc) + timedelta(hours=24),
            "iat": datetime.now(timezone.utc)
        }
        
        token = create_purpose_token(payload, JWT_SECRET)
        
        assert token is not None
        decoded = pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        assert decoded["purpose"] == "email_verification"
    
    def test_create_purpose_token_no_jti_header(self):
        """Test that purpose token does not have JTI header."""
        payload = {
            "purpose": "invitation",
            "exp": datetime.now(timezone.utc) + timedelta(hours=24)
        }
        
        token = create_purpose_token(payload, JWT_SECRET)
        
        headers = pyjwt.get_unverified_header(token)
        assert "jti" not in headers


class TestDecodePurposeToken:
    """Tests for decode_purpose_token function."""
    
    def test_decode_purpose_token_valid(self):
        """Test decoding a valid purpose token."""
        payload = {
            "purpose": "email_verification",
            "user_id": "user-123",
            "exp": datetime.now(timezone.utc) + timedelta(hours=24),
            "iat": datetime.now(timezone.utc)
        }
        token = create_purpose_token(payload, JWT_SECRET)
        
        decoded = decode_purpose_token(token, JWT_SECRET, expected_purpose="email_verification")
        
        assert decoded["purpose"] == "email_verification"
        assert decoded["user_id"] == "user-123"
    
    def test_decode_purpose_token_wrong_purpose(self):
        """Test decoding token with wrong purpose raises ValueError."""
        payload = {
            "purpose": "email_verification",
            "exp": datetime.now(timezone.utc) + timedelta(hours=24)
        }
        token = create_purpose_token(payload, JWT_SECRET)
        
        with pytest.raises(ValueError) as exc_info:
            decode_purpose_token(token, JWT_SECRET, expected_purpose="invitation")
        
        assert "Invalid token purpose" in str(exc_info.value)
    
    def test_decode_purpose_token_expired(self):
        """Test decoding expired token raises exception."""
        payload = {
            "purpose": "email_verification",
            "exp": datetime.now(timezone.utc) - timedelta(hours=1)
        }
        token = create_purpose_token(payload, JWT_SECRET)
        
        with pytest.raises(pyjwt.ExpiredSignatureError):
            decode_purpose_token(token, JWT_SECRET)


class TestVerifyToken:
    """Tests for VerifyToken class."""

    def test_verify_token_valid(self, valid_jwt_token, mock_audit_logger):
        """Test verifying a valid token."""
        verifier = VerifyToken(mock_audit_logger)

        error, code, result = verifier(valid_jwt_token)

        assert error is None
        assert code == 200
        assert isinstance(result, VerifiedTokenData)
        assert result.email == "test@example.com"
        assert result.user_id == "user-123-uuid"
        assert result.tenant_id == "tenant-456-uuid"
        assert result.role == "admin"

    def test_verify_token_expired(self, expired_jwt_token, mock_audit_logger):
        """Test verifying an expired token returns an auth error tuple."""
        verifier = VerifyToken(mock_audit_logger)

        error, code, result = verifier(expired_jwt_token)

        assert error.startswith("Expired token:")
        assert code == 401
        assert result is None

    def test_verify_token_invalid_signature(self, mock_audit_logger):
        """Test verifying token with invalid signature."""
        payload = {
            "sub": "user@example.com",
            "user_id": "user-123",
            "tenant_id": "tenant-456",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1)
        }
        token = pyjwt.encode(payload, "wrong-secret", algorithm="HS256")

        verifier = VerifyToken(mock_audit_logger)

        error, code, result = verifier(token)

        assert error.startswith("Invalid signature:")
        assert code == 401
        assert result is None

    def test_verify_token_missing_sub(self, mock_audit_logger):
        """Test verifying token without sub field returns an auth error tuple."""
        payload = {
            "user_id": "user-123",
            "tenant_id": "tenant-456",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1)
        }
        token = pyjwt.encode(payload, JWT_SECRET, algorithm="HS256")

        verifier = VerifyToken(mock_audit_logger)

        error, code, result = verifier(token)

        assert "missing 'sub'" in error
        assert code == 401
        assert result is None

    def test_verify_token_missing_tenant_id(self, mock_audit_logger):
        """Test verifying token without tenant_id field returns an auth error tuple."""
        payload = {
            "sub": "user@example.com",
            "user_id": "user-123",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1)
        }
        token = pyjwt.encode(payload, JWT_SECRET, algorithm="HS256")

        verifier = VerifyToken(mock_audit_logger)

        error, code, result = verifier(token)

        assert "missing 'tenant_id'" in error
        assert code == 401
        assert result is None


class TestExtractToken:
    """Tests for extract_token function."""

    def test_extract_token_valid(self):
        """Test extracting token from valid Authorization header."""
        mock_request = MagicMock()
        mock_request.headers.get.return_value = "Bearer valid-token-here"

        error, code, token = extract_token(mock_request)

        assert error is None
        assert code == 200
        assert token == "valid-token-here"

    def test_extract_token_missing_header(self):
        """Test extracting token when header is missing."""
        mock_request = MagicMock()
        mock_request.headers.get.return_value = None

        error, code, token = extract_token(mock_request)

        assert error == "Authorization header missing"
        assert code == 401
        assert token is None

    def test_extract_token_wrong_scheme(self):
        """Test extracting token with wrong auth scheme returns an auth error tuple."""
        mock_request = MagicMock()
        mock_request.headers.get.return_value = "Basic dXNlcjpwYXNz"

        error, code, token = extract_token(mock_request)

        assert error == "Invalid scheme. Expected 'Bearer'"
        assert code == 401
        assert token is None

    def test_extract_token_malformed_header(self):
        """Test extracting token from malformed header."""
        mock_request = MagicMock()
        mock_request.headers.get.return_value = "BearerNoSpace"

        error, code, token = extract_token(mock_request)

        assert error == "Malformed Authorization header"
        assert code == 401
        assert token is None


class TestVerifiedTokenData:
    """Tests for VerifiedTokenData namedtuple."""
    
    def test_verified_token_data_creation(self):
        """Test creating VerifiedTokenData instance."""
        data = VerifiedTokenData(
            email="user@example.com",
            tenant_id="tenant-123",
            policy={"users": 7},
            role="admin",
            user_id="user-456",
            exp=1234567890,
            iat=1234567800,
            aud="hexshare-client"
        )
        
        assert data.email == "user@example.com"
        assert data.tenant_id == "tenant-123"
        assert data.policy == {"users": 7}
        assert data.role == "admin"
        assert data.user_id == "user-456"
    
    def test_verified_token_data_is_immutable(self):
        """Test that VerifiedTokenData is immutable."""
        data = VerifiedTokenData(
            email="user@example.com",
            tenant_id="tenant-123",
            policy={},
            role="user",
            user_id="user-456",
            exp=1234567890,
            iat=1234567800,
            aud="hexshare-client"
        )
        
        with pytest.raises(AttributeError):
            data.email = "new@example.com"
