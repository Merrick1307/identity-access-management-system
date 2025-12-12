"""
Tests for app/models/authz.py - Authorization models.
"""
import pytest
from fastapi import HTTPException

from app.models.authz import Action, Authorize


class TestActionIntFlag:
    """Tests for Action IntFlag enum."""
    
    def test_action_read_value(self):
        """Test READ action has correct bit value."""
        assert Action.READ == 1
        assert Action.READ == (1 << 0)
    
    def test_action_write_value(self):
        """Test WRITE action has correct bit value."""
        assert Action.WRITE == 2
        assert Action.WRITE == (1 << 1)
    
    def test_action_delete_value(self):
        """Test DELETE action has correct bit value."""
        assert Action.DELETE == 4
        assert Action.DELETE == (1 << 2)
    
    def test_action_bitwise_or(self):
        """Test combining actions with bitwise OR."""
        combined = Action.READ | Action.WRITE
        
        assert combined == 3
        assert (combined & Action.READ) == Action.READ
        assert (combined & Action.WRITE) == Action.WRITE
        assert (combined & Action.DELETE) == 0
    
    def test_action_bitwise_and(self):
        """Test checking actions with bitwise AND."""
        combined = Action.READ | Action.WRITE | Action.DELETE
        
        assert (combined & Action.READ) == Action.READ
        assert (combined & Action.WRITE) == Action.WRITE
        assert (combined & Action.APPROVE) == 0
    
    def test_action_all_values_unique(self):
        """Test that all action values are unique powers of 2."""
        all_actions = [
            Action.READ, Action.WRITE, Action.DELETE,
            Action.APPROVE, Action.REJECT, Action.EXECUTE,
            Action.ASSIGN, Action.MANAGE, Action.EXPORT,
            Action.IMPORT, Action.ACTIVATE, Action.ARCHIVE
        ]
        
        values = [int(a) for a in all_actions]
        assert len(values) == len(set(values))
        
        for val in values:
            assert val > 0
            assert (val & (val - 1)) == 0
    
    def test_action_combined_has_all(self):
        """Test combined actions contain all individual actions."""
        combined = Action.READ | Action.WRITE | Action.DELETE
        
        assert (combined & Action.READ) == Action.READ
        assert (combined & Action.WRITE) == Action.WRITE
        assert (combined & Action.DELETE) == Action.DELETE


class TestAuthorizeModel:
    """Tests for Authorize Pydantic model."""
    
    def test_authorize_valid_fga(self):
        """Test creating valid FGA authorization request."""
        auth = Authorize(
            action="read",
            resource="documents",
            conditions_to_check=None,
            grant_type="fga"
        )
        
        assert auth.action == "read"
        assert auth.resource == "documents"
        assert auth.grant_type == "fga"
        assert auth.check_condition is False
    
    def test_authorize_valid_rba(self):
        """Test creating valid RBA authorization request."""
        auth = Authorize(
            action="manage",
            resource="users",
            conditions_to_check=None,
            grant_type="rba"
        )
        
        assert auth.grant_type == "rba"
    
    def test_authorize_invalid_grant_type(self):
        """Test that invalid grant_type raises HTTPException."""
        with pytest.raises(HTTPException) as exc_info:
            Authorize(
                action="read",
                resource="documents",
                conditions_to_check=None,
                grant_type="invalid"
            )
        
        assert exc_info.value.status_code == 400
        assert "fga or rba" in exc_info.value.detail
    
    def test_authorize_with_conditions(self):
        """Test authorization request with conditions."""
        auth = Authorize(
            action="write",
            resource="documents",
            check_condition=True,
            conditions_to_check={"department": "engineering", "validity_time": True}
        )
        
        assert auth.check_condition is True
        assert auth.conditions_to_check["department"] == "engineering"
    
    def test_authorize_check_condition_without_conditions(self):
        """Test that check_condition=True without conditions raises HTTPException."""
        with pytest.raises(HTTPException) as exc_info:
            Authorize(
                action="read",
                resource="documents",
                check_condition=True,
                conditions_to_check=None
            )
        
        assert exc_info.value.status_code == 400
        assert "conditions_to_check" in exc_info.value.detail
    
    def test_authorize_check_condition_empty_conditions(self):
        """Test that check_condition=True with empty conditions raises HTTPException."""
        with pytest.raises(HTTPException) as exc_info:
            Authorize(
                action="read",
                resource="documents",
                check_condition=True,
                conditions_to_check={}
            )
        
        assert exc_info.value.status_code == 400
    
    def test_authorize_default_check_condition(self):
        """Test Authorize model default check_condition value."""
        auth = Authorize(
            action="read",
            resource="users",
            conditions_to_check=None
        )
        
        assert auth.check_condition is False
        assert auth.conditions_to_check is None
        assert auth.grant_type == "fga"
    
    def test_authorize_optional_resource(self):
        """Test that resource can be None."""
        auth = Authorize(
            action="read",
            resource=None,
            conditions_to_check=None
        )
        
        assert auth.resource is None
