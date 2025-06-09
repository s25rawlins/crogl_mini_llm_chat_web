"""
Tests for Database Manager

This module contains tests for the database manager that handles
backend selection and initialization.
"""

from unittest.mock import MagicMock, Mock, patch

import pytest

from mini_llm_chat.backends import InMemoryBackend, PostgreSQLBackend
from mini_llm_chat.database_manager import (
    DatabaseConnectionError,
    DatabaseManager,
    get_database_manager,
    initialize_database,
)


class TestDatabaseManager:
    """Test cases for the DatabaseManager class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.manager = DatabaseManager()

    def test_initialize_memory_backend(self):
        """Test initializing in-memory backend."""
        backend = self.manager.initialize_backend("memory")

        assert isinstance(backend, InMemoryBackend)
        assert backend.get_backend_info()["type"] == "memory"
        assert not backend.supports_persistence()
        assert self.manager._initialized

    @patch("mini_llm_chat.database_manager.PostgreSQLBackend")
    def test_initialize_postgresql_backend(self, mock_postgresql):
        """Test initializing PostgreSQL backend."""
        mock_backend = Mock()
        mock_backend.get_backend_info.return_value = {
            "name": "PostgreSQL",
            "type": "postgresql",
        }
        mock_backend.supports_persistence.return_value = True
        mock_backend.ensure_database_ready.return_value = True
        mock_postgresql.return_value = mock_backend

        backend = self.manager.initialize_backend("postgresql")

        assert backend == mock_backend
        mock_postgresql.assert_called_once()
        mock_backend.ensure_database_ready.assert_called_once()

    @patch("mini_llm_chat.database_manager.PostgreSQLBackend")
    def test_initialize_postgresql_with_fallback(self, mock_postgresql):
        """Test PostgreSQL initialization with fallback to memory."""
        # Make PostgreSQL initialization fail
        mock_postgresql.side_effect = Exception("Connection failed")

        backend = self.manager.initialize_backend("postgresql", fallback_to_memory=True)

        assert isinstance(backend, InMemoryBackend)
        assert backend.get_backend_info()["type"] == "memory"

    @patch("mini_llm_chat.database_manager.PostgreSQLBackend")
    def test_initialize_postgresql_without_fallback(self, mock_postgresql):
        """Test PostgreSQL initialization without fallback."""
        # Make PostgreSQL initialization fail
        mock_postgresql.side_effect = Exception("Connection failed")

        with pytest.raises(DatabaseConnectionError):
            self.manager.initialize_backend("postgresql", fallback_to_memory=False)

    @patch("mini_llm_chat.database_manager.PostgreSQLBackend")
    def test_initialize_auto_backend_postgresql_success(self, mock_postgresql):
        """Test auto backend selection with successful PostgreSQL."""
        mock_backend = Mock()
        mock_backend.get_backend_info.return_value = {
            "name": "PostgreSQL",
            "type": "postgresql",
        }
        mock_postgresql.return_value = mock_backend

        backend = self.manager.initialize_backend("auto")

        assert backend == mock_backend
        mock_postgresql.assert_called_once()

    @patch("mini_llm_chat.database_manager.PostgreSQLBackend")
    def test_initialize_auto_backend_fallback_to_memory(self, mock_postgresql):
        """Test auto backend selection with fallback to memory."""
        # Make PostgreSQL initialization fail
        mock_postgresql.side_effect = Exception("Connection failed")

        backend = self.manager.initialize_backend("auto")

        assert isinstance(backend, InMemoryBackend)
        assert backend.get_backend_info()["type"] == "memory"

    def test_initialize_invalid_backend(self):
        """Test initialization with invalid backend type."""
        with pytest.raises(ValueError):
            self.manager.initialize_backend("invalid")

    def test_get_backend_before_initialization(self):
        """Test getting backend before initialization."""
        with pytest.raises(RuntimeError):
            self.manager.get_backend()

    def test_get_backend_info_before_initialization(self):
        """Test getting backend info before initialization."""
        info = self.manager.get_backend_info()
        assert info["name"] == "None"
        assert not info["initialized"]

    def test_get_backend_info_after_initialization(self):
        """Test getting backend info after initialization."""
        backend = self.manager.initialize_backend("memory")
        info = self.manager.get_backend_info()

        assert info["name"] == "In-Memory"
        assert info["type"] == "memory"
        assert info["initialized"]

    def test_supports_persistence(self):
        """Test persistence support check."""
        # Before initialization
        assert not self.manager.supports_persistence()

        # After memory backend initialization
        self.manager.initialize_backend("memory")
        assert not self.manager.supports_persistence()

    @patch("builtins.input")
    def test_prompt_for_fallback_yes(self, mock_input):
        """Test user prompt for fallback - yes response."""
        mock_input.return_value = "y"

        result = self.manager.prompt_for_fallback()
        assert result

    @patch("builtins.input")
    def test_prompt_for_fallback_no(self, mock_input):
        """Test user prompt for fallback - no response."""
        mock_input.return_value = "n"

        result = self.manager.prompt_for_fallback()
        assert not result

    @patch("builtins.input")
    def test_prompt_for_fallback_keyboard_interrupt(self, mock_input):
        """Test user prompt for fallback - keyboard interrupt."""
        mock_input.side_effect = KeyboardInterrupt()

        result = self.manager.prompt_for_fallback()
        assert not result


class TestDatabaseManagerFunctions:
    """Test cases for database manager utility functions."""

    @patch("mini_llm_chat.database_manager._db_manager")
    def test_get_database_manager(self, mock_manager):
        """Test getting global database manager."""
        result = get_database_manager()
        assert result == mock_manager

    @patch("mini_llm_chat.database_manager.get_database_manager")
    def test_initialize_database(self, mock_get_manager):
        """Test database initialization function."""
        mock_manager = Mock()
        mock_backend = Mock()
        mock_manager.initialize_backend.return_value = mock_backend
        mock_get_manager.return_value = mock_manager

        result = initialize_database("memory")

        assert result == mock_backend
        mock_manager.initialize_backend.assert_called_once_with("memory", False, None)

    @patch("mini_llm_chat.database_manager.get_database_manager")
    def test_initialize_database_with_interactive_fallback(self, mock_get_manager):
        """Test database initialization with interactive fallback."""
        mock_manager = Mock()
        mock_manager.initialize_backend.side_effect = DatabaseConnectionError("Failed")
        mock_manager.prompt_for_fallback.return_value = True
        mock_backend = Mock()

        # First call fails, second call (fallback) succeeds
        mock_manager.initialize_backend.side_effect = [
            DatabaseConnectionError("Failed"),
            mock_backend,
        ]
        mock_get_manager.return_value = mock_manager

        result = initialize_database("postgresql", interactive_fallback=True)

        assert result == mock_backend
        assert mock_manager.initialize_backend.call_count == 2
        mock_manager.prompt_for_fallback.assert_called_once()

    @patch("mini_llm_chat.database_manager.get_database_manager")
    def test_initialize_database_interactive_fallback_declined(self, mock_get_manager):
        """Test database initialization with declined interactive fallback."""
        mock_manager = Mock()
        mock_manager.initialize_backend.side_effect = DatabaseConnectionError("Failed")
        mock_manager.prompt_for_fallback.return_value = False
        mock_get_manager.return_value = mock_manager

        with pytest.raises(DatabaseConnectionError):
            initialize_database("postgresql", interactive_fallback=True)

        mock_manager.prompt_for_fallback.assert_called_once()


class TestConvenienceFunctions:
    """Test cases for convenience functions that delegate to the backend."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_backend = Mock()
        self.mock_manager = Mock()
        self.mock_manager.get_backend.return_value = self.mock_backend

    @patch("mini_llm_chat.database_manager.get_database_manager")
    def test_init_db(self, mock_get_manager):
        """Test init_db convenience function."""
        mock_get_manager.return_value = self.mock_manager

        from mini_llm_chat.database_manager import init_db

        init_db()

        self.mock_backend.init_db.assert_called_once()

    @patch("mini_llm_chat.database_manager.get_database_manager")
    def test_create_admin_user(self, mock_get_manager):
        """Test create_admin_user convenience function."""
        mock_get_manager.return_value = self.mock_manager
        self.mock_backend.create_admin_user.return_value = True

        from mini_llm_chat.database_manager import create_admin_user

        result = create_admin_user("admin", "admin@test.com", "password")

        assert result
        self.mock_backend.create_admin_user.assert_called_once_with(
            "admin", "admin@test.com", "password"
        )

    @patch("mini_llm_chat.database_manager.get_database_manager")
    def test_authenticate_user(self, mock_get_manager):
        """Test authenticate_user convenience function."""
        mock_get_manager.return_value = self.mock_manager
        mock_user = Mock()
        self.mock_backend.authenticate_user.return_value = mock_user

        from mini_llm_chat.database_manager import authenticate_user

        result = authenticate_user("testuser", "password")

        assert result == mock_user
        self.mock_backend.authenticate_user.assert_called_once_with(
            "testuser", "password"
        )

    @patch("mini_llm_chat.database_manager.get_database_manager")
    def test_get_session_user(self, mock_get_manager):
        """Test get_session_user convenience function."""
        mock_get_manager.return_value = self.mock_manager
        mock_user = Mock()
        self.mock_backend.get_session_user.return_value = mock_user

        from mini_llm_chat.database_manager import get_session_user

        result = get_session_user()

        assert result == mock_user
        self.mock_backend.get_session_user.assert_called_once()

    @patch("mini_llm_chat.database_manager.get_database_manager")
    def test_get_session_user_not_supported(self, mock_get_manager):
        """Test get_session_user when backend doesn't support it."""
        mock_get_manager.return_value = self.mock_manager
        # Backend doesn't have get_session_user method
        del self.mock_backend.get_session_user

        from mini_llm_chat.database_manager import get_session_user

        result = get_session_user()

        assert result is None
