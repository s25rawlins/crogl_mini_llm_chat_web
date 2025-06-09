"""
Database Tests Module

This module contains comprehensive unit tests for the database functionality.
It tests models, database operations, authentication, and conversation management.
"""

import os
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mini_llm_chat.database import (
    Base,
    Conversation,
    Message,
    User,
    add_message,
    authenticate_user,
    create_admin_user,
    create_conversation,
    get_conversation_messages,
    get_db,
    get_user_by_token,
    init_db,
    truncate_conversation_messages,
)


class TestUserModel:
    """Test cases for the User model."""

    def test_user_creation(self):
        """Test creating a User instance."""
        user = User(
            username="testuser", email="test@example.com", role="user", is_active=True
        )

        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.role == "user"
        assert user.is_active is True

    def test_set_password(self):
        """Test password hashing functionality."""
        user = User(username="testuser", email="test@example.com")
        password = "testpassword123"

        user.set_password(password)

        assert user.hashed_password is not None
        assert user.hashed_password != password  # Should be hashed
        assert len(user.hashed_password) > 0

    def test_verify_password_correct(self):
        """Test password verification with correct password."""
        user = User(username="testuser", email="test@example.com")
        password = "testpassword123"

        user.set_password(password)

        assert user.verify_password(password) is True

    def test_verify_password_incorrect(self):
        """Test password verification with incorrect password."""
        user = User(username="testuser", email="test@example.com")
        password = "testpassword123"
        wrong_password = "wrongpassword"

        user.set_password(password)

        assert user.verify_password(wrong_password) is False

    def test_is_admin_true(self):
        """Test is_admin method for admin user."""
        user = User(username="admin", email="admin@example.com", role="admin")

        assert user.is_admin() is True

    def test_is_admin_false(self):
        """Test is_admin method for regular user."""
        user = User(username="user", email="user@example.com", role="user")

        assert user.is_admin() is False

    def test_generate_token(self):
        """Test JWT token generation."""
        user = User(id=1, username="testuser", email="test@example.com", role="user")

        token = user.generate_token()

        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0

    def test_verify_token_valid(self):
        """Test JWT token verification with valid token."""
        user = User(id=1, username="testuser", email="test@example.com", role="user")

        token = user.generate_token()
        payload = User.verify_token(token)

        assert payload is not None
        assert payload["user_id"] == 1
        assert payload["username"] == "testuser"
        assert payload["role"] == "user"

    def test_verify_token_invalid(self):
        """Test JWT token verification with invalid token."""
        invalid_token = "invalid.token.here"

        payload = User.verify_token(invalid_token)

        assert payload is None

    @patch("mini_llm_chat.database.jwt.decode")
    def test_verify_token_expired(self, mock_decode):
        """Test JWT token verification with expired token."""
        from jwt import ExpiredSignatureError

        mock_decode.side_effect = ExpiredSignatureError()

        payload = User.verify_token("expired.token")

        assert payload is None


class TestConversationModel:
    """Test cases for the Conversation model."""

    def test_conversation_creation(self):
        """Test creating a Conversation instance."""
        conversation = Conversation(user_id=1, title="Test Chat")

        assert conversation.user_id == 1
        assert conversation.title == "Test Chat"
        # Note: created_at and updated_at are set by SQLAlchemy defaults
        # and are only populated when the object is added to a session


class TestMessageModel:
    """Test cases for the Message model."""

    def test_message_creation(self):
        """Test creating a Message instance."""
        message = Message(
            conversation_id=1, role="user", content="Hello, world!", token_count=3
        )

        assert message.conversation_id == 1
        assert message.role == "user"
        assert message.content == "Hello, world!"
        assert message.token_count == 3
        # Note: created_at is set by SQLAlchemy default
        # and is only populated when the object is added to a session


class TestDatabaseOperations:
    """Test cases for database operations."""

    @patch("mini_llm_chat.database.Base.metadata.create_all")
    def test_init_db_success(self, mock_create_all):
        """Test successful database initialization."""
        init_db()

        mock_create_all.assert_called_once()

    @patch("mini_llm_chat.database.Base.metadata.create_all")
    def test_init_db_failure(self, mock_create_all):
        """Test database initialization failure."""
        mock_create_all.side_effect = Exception("Database error")

        with pytest.raises(Exception):
            init_db()

    @patch("mini_llm_chat.database.get_db")
    def test_create_admin_user_success(self, mock_get_db):
        """Test successful admin user creation."""
        # Mock database session
        mock_session = MagicMock()
        mock_get_db.return_value = mock_session

        # Mock query to return None (user doesn't exist)
        mock_session.query.return_value.filter.return_value.first.return_value = None

        result = create_admin_user("admin", "admin@example.com", "password123")

        assert result is True
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()

    @patch("mini_llm_chat.database.get_db")
    def test_create_admin_user_already_exists(self, mock_get_db):
        """Test admin user creation when user already exists."""
        # Mock database session
        mock_session = MagicMock()
        mock_get_db.return_value = mock_session

        # Mock query to return existing user
        existing_user = User(username="admin", email="admin@example.com")
        mock_session.query.return_value.filter.return_value.first.return_value = (
            existing_user
        )

        result = create_admin_user("admin", "admin@example.com", "password123")

        assert result is False
        mock_session.add.assert_not_called()

    @patch("mini_llm_chat.database.get_db")
    def test_create_admin_user_database_error(self, mock_get_db):
        """Test admin user creation with database error."""
        # Mock database session
        mock_session = MagicMock()
        mock_get_db.return_value = mock_session

        # Mock query to return None, but commit raises exception
        mock_session.query.return_value.filter.return_value.first.return_value = None
        mock_session.commit.side_effect = Exception("Database error")

        result = create_admin_user("admin", "admin@example.com", "password123")

        assert result is False
        mock_session.rollback.assert_called_once()

    @patch("mini_llm_chat.database.get_db")
    def test_authenticate_user_success(self, mock_get_db):
        """Test successful user authentication."""
        # Mock database session
        mock_session = MagicMock()
        mock_get_db.return_value = mock_session

        # Create a real user for password verification
        user = User(username="testuser", email="test@example.com", is_active=True)
        user.set_password("password123")

        # Mock query to return the user
        mock_session.query.return_value.filter.return_value.first.return_value = user

        result = authenticate_user("testuser", "password123")

        assert result is not None
        assert result.username == "testuser"
        mock_session.commit.assert_called_once()  # For updating last_login

    @patch("mini_llm_chat.database.get_db")
    def test_authenticate_user_wrong_password(self, mock_get_db):
        """Test user authentication with wrong password."""
        # Mock database session
        mock_session = MagicMock()
        mock_get_db.return_value = mock_session

        # Create a real user for password verification
        user = User(username="testuser", email="test@example.com", is_active=True)
        user.set_password("password123")

        # Mock query to return the user
        mock_session.query.return_value.filter.return_value.first.return_value = user

        result = authenticate_user("testuser", "wrongpassword")

        assert result is None

    @patch("mini_llm_chat.database.get_db")
    def test_authenticate_user_not_found(self, mock_get_db):
        """Test user authentication when user doesn't exist."""
        # Mock database session
        mock_session = MagicMock()
        mock_get_db.return_value = mock_session

        # Mock query to return None
        mock_session.query.return_value.filter.return_value.first.return_value = None

        result = authenticate_user("nonexistent", "password123")

        assert result is None

    @patch("mini_llm_chat.database.get_db")
    def test_authenticate_user_database_error(self, mock_get_db):
        """Test user authentication with database error."""
        # Mock database session
        mock_session = MagicMock()
        mock_get_db.return_value = mock_session

        # Mock query to raise exception
        mock_session.query.side_effect = Exception("Database error")

        result = authenticate_user("testuser", "password123")

        assert result is None

    @patch("mini_llm_chat.database.User.verify_token")
    @patch("mini_llm_chat.database.get_db")
    def test_get_user_by_token_success(self, mock_get_db, mock_verify_token):
        """Test successful user retrieval by token."""
        # Mock database session
        mock_session = MagicMock()
        mock_get_db.return_value = mock_session

        # Mock token verification
        mock_verify_token.return_value = {"user_id": 1, "username": "testuser"}

        # Mock user query
        user = User(id=1, username="testuser", email="test@example.com", is_active=True)
        mock_session.query.return_value.filter.return_value.first.return_value = user

        result = get_user_by_token("valid.token")

        assert result is not None
        assert result.username == "testuser"

    @patch("mini_llm_chat.database.User.verify_token")
    def test_get_user_by_token_invalid_token(self, mock_verify_token):
        """Test user retrieval with invalid token."""
        mock_verify_token.return_value = None

        result = get_user_by_token("invalid.token")

        assert result is None

    @patch("mini_llm_chat.database.get_db")
    def test_create_conversation_success(self, mock_get_db):
        """Test successful conversation creation."""
        # Mock database session
        mock_session = MagicMock()
        mock_get_db.return_value = mock_session

        # Mock the conversation object that would be returned after commit
        mock_conversation = Conversation(id=1, user_id=1, title="Test Chat")
        mock_session.add.return_value = None
        mock_session.commit.return_value = None
        mock_session.refresh.return_value = None

        # We need to simulate what happens when we create and add the conversation
        def mock_add(conversation):
            conversation.id = 1

        mock_session.add.side_effect = mock_add

        result = create_conversation(1, "Test Chat")

        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()

    @patch("mini_llm_chat.database.get_db")
    def test_create_conversation_database_error(self, mock_get_db):
        """Test conversation creation with database error."""
        # Mock database session
        mock_session = MagicMock()
        mock_get_db.return_value = mock_session

        # Mock commit to raise exception
        mock_session.commit.side_effect = Exception("Database error")

        result = create_conversation(1, "Test Chat")

        assert result is None
        mock_session.rollback.assert_called_once()

    @patch("mini_llm_chat.database.get_db")
    def test_add_message_success(self, mock_get_db):
        """Test successful message addition."""
        # Mock database session
        mock_session = MagicMock()
        mock_get_db.return_value = mock_session

        result = add_message(1, "user", "Hello, world!", 3)

        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()

    @patch("mini_llm_chat.database.get_db")
    def test_add_message_database_error(self, mock_get_db):
        """Test message addition with database error."""
        # Mock database session
        mock_session = MagicMock()
        mock_get_db.return_value = mock_session

        # Mock commit to raise exception
        mock_session.commit.side_effect = Exception("Database error")

        result = add_message(1, "user", "Hello, world!", 3)

        assert result is None
        mock_session.rollback.assert_called_once()

    @patch("mini_llm_chat.database.get_db")
    def test_get_conversation_messages_success(self, mock_get_db):
        """Test successful conversation messages retrieval."""
        # Mock database session
        mock_session = MagicMock()
        mock_get_db.return_value = mock_session

        # Mock messages
        messages = [
            Message(id=1, conversation_id=1, role="user", content="Hello"),
            Message(id=2, conversation_id=1, role="assistant", content="Hi there!"),
        ]
        mock_session.query.return_value.filter.return_value.order_by.return_value.all.return_value = (
            messages
        )

        result = get_conversation_messages(1)

        assert len(result) == 2
        assert result[0].content == "Hello"
        assert result[1].content == "Hi there!"

    @patch("mini_llm_chat.database.get_db")
    def test_get_conversation_messages_with_limit(self, mock_get_db):
        """Test conversation messages retrieval with limit."""
        # Mock database session
        mock_session = MagicMock()
        mock_get_db.return_value = mock_session

        # Mock query chain
        mock_query = mock_session.query.return_value
        mock_filter = mock_query.filter.return_value
        mock_order = mock_filter.order_by.return_value
        mock_limit = mock_order.limit.return_value
        mock_limit.all.return_value = []

        get_conversation_messages(1, limit=10)

        mock_order.limit.assert_called_once_with(10)

    @patch("mini_llm_chat.database.get_db")
    def test_get_conversation_messages_database_error(self, mock_get_db):
        """Test conversation messages retrieval with database error."""
        # Mock database session
        mock_session = MagicMock()
        mock_get_db.return_value = mock_session

        # Mock query to raise exception
        mock_session.query.side_effect = Exception("Database error")

        result = get_conversation_messages(1)

        assert result == []

    @patch("mini_llm_chat.database.get_db")
    def test_truncate_conversation_messages_no_truncation_needed(self, mock_get_db):
        """Test message truncation when no truncation is needed."""
        # Mock database session
        mock_session = MagicMock()
        mock_get_db.return_value = mock_session

        # Mock count to return less than max_messages
        mock_session.query.return_value.filter.return_value.count.return_value = 5

        result = truncate_conversation_messages(1, 10)

        assert result is True
        mock_session.delete.assert_not_called()

    @patch("mini_llm_chat.database.get_db")
    def test_truncate_conversation_messages_success(self, mock_get_db):
        """Test successful message truncation."""
        # Mock database session
        mock_session = MagicMock()
        mock_get_db.return_value = mock_session

        # Mock count to return more than max_messages
        mock_session.query.return_value.filter.return_value.count.return_value = 15

        # Mock messages to delete
        messages_to_delete = [
            Message(id=1, conversation_id=1, role="user", content="Old message 1"),
            Message(id=2, conversation_id=1, role="user", content="Old message 2"),
        ]

        # Mock the query chain for getting messages to delete
        mock_query = mock_session.query.return_value
        mock_filter = mock_query.filter.return_value
        mock_order = mock_filter.order_by.return_value
        mock_limit = mock_order.limit.return_value
        mock_limit.all.return_value = messages_to_delete

        result = truncate_conversation_messages(1, 10)

        assert result is True
        assert mock_session.delete.call_count == 2  # Two messages deleted
        mock_session.commit.assert_called_once()

    @patch("mini_llm_chat.database.get_db")
    def test_truncate_conversation_messages_database_error(self, mock_get_db):
        """Test message truncation with database error."""
        # Mock database session
        mock_session = MagicMock()
        mock_get_db.return_value = mock_session

        # Mock count to raise exception
        mock_session.query.side_effect = Exception("Database error")

        result = truncate_conversation_messages(1, 10)

        assert result is False
        mock_session.rollback.assert_called_once()


class TestDatabaseConfiguration:
    """Test cases for database configuration."""

    @patch.dict(os.environ, {"DATABASE_URL": "postgresql://test:test@localhost/test"})
    def test_database_url_from_environment(self):
        """Test that DATABASE_URL is read from environment."""
        # Re-import to get the updated environment variable
        import importlib

        import mini_llm_chat.database

        importlib.reload(mini_llm_chat.database)

        assert (
            mini_llm_chat.database.DATABASE_URL
            == "postgresql://test:test@localhost/test"
        )

    @patch.dict(os.environ, {"JWT_SECRET_KEY": "test-secret-key"})
    def test_jwt_secret_from_environment(self):
        """Test that JWT_SECRET_KEY is read from environment."""
        # Re-import to get the updated environment variable
        import importlib

        import mini_llm_chat.database

        importlib.reload(mini_llm_chat.database)

        assert mini_llm_chat.database.JWT_SECRET_KEY == "test-secret-key"

    def test_get_db_function(self):
        """Test the get_db function returns a session."""
        # This is a basic test since we can't easily mock the SessionLocal
        session = get_db()
        assert session is not None


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__])
