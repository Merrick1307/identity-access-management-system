"""
Tests for app/core/security.py - Security utilities.
"""
import pytest
import bcrypt

from app.core.security import hash_password


class TestHashPassword:
    """Tests for hash_password function."""
    
    def test_hash_password_returns_string(self):
        """Test that hash_password returns a string."""
        result = hash_password("testpassword123")
        
        assert isinstance(result, str)
    
    def test_hash_password_is_bcrypt_hash(self):
        """Test that the result is a valid bcrypt hash."""
        result = hash_password("testpassword123")
        
        assert result.startswith("$2b$")
    
    def test_hash_password_different_for_same_input(self):
        """Test that same password produces different hashes (salt)."""
        password = "samepassword"
        
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        
        assert hash1 != hash2
    
    def test_hash_password_verifiable(self):
        """Test that hashed password can be verified."""
        password = "verifyablepassword"
        hashed = hash_password(password)
        
        is_valid = bcrypt.checkpw(password.encode(), hashed.encode())
        
        assert is_valid is True
    
    def test_hash_password_wrong_password_fails(self):
        """Test that wrong password fails verification."""
        hashed = hash_password("correctpassword")
        
        is_valid = bcrypt.checkpw(b"wrongpassword", hashed.encode())
        
        assert is_valid is False
    
    def test_hash_password_handles_unicode(self):
        """Test hashing passwords with unicode characters."""
        password = "пароль123日本語"
        hashed = hash_password(password)
        
        is_valid = bcrypt.checkpw(password.encode(), hashed.encode())
        
        assert is_valid is True
    
    def test_hash_password_handles_empty_string(self):
        """Test hashing empty password."""
        hashed = hash_password("")
        
        is_valid = bcrypt.checkpw(b"", hashed.encode())
        
        assert is_valid is True
    
    def test_hash_password_handles_long_password(self):
        """Test hashing very long password."""
        long_password = "a" * 72
        hashed = hash_password(long_password)
        
        is_valid = bcrypt.checkpw(long_password.encode(), hashed.encode())
        
        assert is_valid is True
