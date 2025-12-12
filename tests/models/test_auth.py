"""
Tests for app/models/auth.py - Authentication models.
"""
import pytest
from pydantic import ValidationError

from app.models.auth import Authentication, BulkRevokeRequest


class TestAuthentication:
    """Tests for Authentication model."""
    
    def test_authentication_valid(self):
        """Test creating valid authentication request."""
        auth = Authentication(
            email="user@example.com",
            password="securepassword123"
        )
        
        assert auth.email == "user@example.com"
        assert auth.password == "securepassword123"
    
    def test_authentication_valid_email_formats(self):
        """Test authentication with various valid email formats."""
        valid_emails = [
            "user@example.com",
            "user.name@example.com",
            "user+tag@example.com",
            "user@subdomain.example.com",
            "user123@example.co.uk"
        ]
        
        for email in valid_emails:
            auth = Authentication(email=email, password="password123")
            assert auth.email == email
    
    def test_authentication_invalid_email(self):
        """Test that invalid email raises ValidationError."""
        invalid_emails = [
            "not-an-email",
            "@example.com",
            "user@",
            "user@.com",
            ""
        ]
        
        for email in invalid_emails:
            with pytest.raises(ValidationError):
                Authentication(email=email, password="password123")
    
    def test_authentication_missing_email(self):
        """Test that missing email raises ValidationError."""
        with pytest.raises(ValidationError):
            Authentication(password="password123")
    
    def test_authentication_missing_password(self):
        """Test that missing password raises ValidationError."""
        with pytest.raises(ValidationError):
            Authentication(email="user@example.com")
    
    def test_authentication_empty_password(self):
        """Test authentication with empty password is allowed by model."""
        auth = Authentication(email="user@example.com", password="")
        assert auth.password == ""
    
    def test_authentication_long_password(self):
        """Test authentication with long password."""
        long_password = "a" * 1000
        auth = Authentication(email="user@example.com", password=long_password)
        assert len(auth.password) == 1000


class TestBulkRevokeRequest:
    """Tests for BulkRevokeRequest model."""
    
    def test_bulk_revoke_request_valid(self):
        """Test creating valid bulk revoke request."""
        request = BulkRevokeRequest(
            jtis=["jti-1", "jti-2", "jti-3"]
        )
        
        assert len(request.jtis) == 3
        assert request.jtis[0] == "jti-1"
    
    def test_bulk_revoke_request_single_jti(self):
        """Test bulk revoke with single JTI."""
        request = BulkRevokeRequest(jtis=["single-jti"])
        
        assert len(request.jtis) == 1
    
    def test_bulk_revoke_request_empty_list(self):
        """Test bulk revoke with empty list is valid."""
        request = BulkRevokeRequest(jtis=[])
        
        assert request.jtis == []
    
    def test_bulk_revoke_request_missing_jtis(self):
        """Test that missing jtis raises ValidationError."""
        with pytest.raises(ValidationError):
            BulkRevokeRequest()
    
    def test_bulk_revoke_request_invalid_type(self):
        """Test that non-list jtis raises ValidationError."""
        with pytest.raises(ValidationError):
            BulkRevokeRequest(jtis="single-string")
    
    def test_bulk_revoke_request_many_jtis(self):
        """Test bulk revoke with many JTIs."""
        jtis = [f"jti-{i}" for i in range(100)]
        request = BulkRevokeRequest(jtis=jtis)
        
        assert len(request.jtis) == 100
