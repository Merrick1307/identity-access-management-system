"""
Tests for app/database/queries/loader.py - SQL query loader.
"""
import pytest

from app.database.queries.loader import QUERIES


class TestQueriesDict:
    """Tests for QUERIES dictionary."""
    
    def test_queries_is_dict(self):
        """Test that QUERIES is a dictionary."""
        assert isinstance(QUERIES, dict)
    
    def test_queries_values_are_strings(self):
        """Test that all query values are strings."""
        for key, value in QUERIES.items():
            assert isinstance(key, str)
            assert isinstance(value, str)
    
    def test_queries_keys_have_no_extension(self):
        """Test that query keys don't have .sql extension."""
        for key in QUERIES.keys():
            assert not key.endswith(".sql")
    
    def test_queries_values_not_empty(self):
        """Test that query values are not empty strings."""
        for key, value in QUERIES.items():
            assert len(value.strip()) > 0, f"Query '{key}' is empty"
