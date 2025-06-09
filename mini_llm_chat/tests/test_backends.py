"""
Tests for Database Backends

This module contains tests for the database backend system, including
both PostgreSQL and in-memory backends.
"""

from datetime import datetime
from unittest.mock import Mock, patch

import pytest

from mini_llm_chat.backends import DatabaseBackend, InMemoryBackend, PostgreSQLBackend
from mini_llm_chat.backends.base import Conversation, Message, User


class TestInMemoryBackend:
    """Test cases for the in-memory database backend."""

    def setup_method(self):
        """Set up test fixtures."""
        self.backend = InMemoryBackend()
        self.backend.init_db()

    def test_init_db(self):
        """Test database initialization."""
        assert len(self.backend.users) == 1  # Session user
        assert "session_user" in self.backend.username_to_id
        assert not self.backend.supports_persistence()

    def test_create_admin_user(self):
        """Test admin user creation."""
        success = self.backend.create_admin_user(
            "admin", "admin@test.com", "password123"
        )
        assert success

        # Try to create same user again
        success = self.backend.create_admin_user(
            "admin", "admin@test.com", "password123"
        )
        assert not success

    def test_authenticate_user(self):
        """Test user authentication."""
        # Create a user first
        self.backend.create_admin_user("testuser", "test@test.com", "password123")

        # Test successful authentication
        user = self.backend.authenticate_user("testuser", "password123")
        assert user is not None
        assert user.username == "testuser"

        # Test failed authentication
        user = self.backend.authenticate_user("testuser", "wrongpassword")
        assert user is None

        # Test session user authentication (any password works)
        user = self.backend.authenticate_user("session_user", "anypassword")
        assert user is not None
        assert user.username == "session_user"

    def test_create_conversation(self):
        """Test conversation creation."""
        # Get session user
        session_user = self.backend.get_session_user()
        assert session_user is not None

        # Create conversation
        conversation = self.backend.create_conversation(session_user.id, "Test Chat")
        assert conversation is not None
        assert conversation.title == "Test Chat"
        assert conversation.user_id == session_user.id

    def test_add_message(self):
        """Test message addition."""
        # Create conversation
        session_user = self.backend.get_session_user()
        conversation = self.backend.create_conversation(session_user.id)

        # Add message
        message = self.backend.add_message(conversation.id, "user", "Hello, world!", 10)
        assert message is not None
        assert message.content == "Hello, world!"
        assert message.role == "user"
        assert message.token_count == 10

    def test_get_conversation_messages(self):
        """Test retrieving conversation messages."""
        # Create conversation and add messages
        session_user = self.backend.get_session_user()
        conversation = self.backend.create_conversation(session_user.id)

        self.backend.add_message(conversation.id, "system", "System message")
        self.backend.add_message(conversation.id, "user", "User message")
        self.backend.add_message(conversation.id, "assistant", "Assistant message")

        # Get all messages
        messages = self.backend.get_conversation_messages(conversation.id)
        assert len(messages) == 3
        assert messages[0].role == "system"
        assert messages[1].role == "user"
        assert messages[2].role == "assistant"

        # Get limited messages
        messages = self.backend.get_conversation_messages(conversation.id, limit=2)
        assert len(messages) == 2

    def test_truncate_conversation_messages(self):
        """Test message truncation."""
        # Create conversation and add many messages
        session_user = self.backend.get_session_user()
        conversation = self.backend.create_conversation(session_user.id)

        # Add system message and user messages
        self.backend.add_message(conversation.id, "system", "System message")
        for i in range(10):
            self.backend.add_message(conversation.id, "user", f"Message {i}")

        # Truncate to 5 messages
        success = self.backend.truncate_conversation_messages(conversation.id, 5)
        assert success

        # Check remaining messages
        messages = self.backend.get_conversation_messages(conversation.id)
        assert len(messages) <= 5
        # System message should be preserved
        assert any(msg.role == "system" for msg in messages)

    def test_get_backend_info(self):
        """Test backend information."""
        info = self.backend.get_backend_info()
        assert info["name"] == "In-Memory"
        assert info["type"] == "memory"
        assert not info["persistent"]
        assert "basic_chat" in info["features"]
        assert "no_persistence" in info["limitations"]


class TestPostgreSQLBackend:
    """Test cases for the PostgreSQL database backend."""

    @patch("mini_llm_chat.backends.postgresql.create_engine")
    @patch("mini_llm_chat.backends.postgresql.sessionmaker")
    def test_init_postgresql_backend(self, mock_sessionmaker, mock_create_engine):
        """Test PostgreSQL backend initialization."""
        mock_engine = Mock()
        mock_create_engine.return_value = mock_engine
        mock_session_class = Mock()
        mock_sessionmaker.return_value = mock_session_class

        backend = PostgreSQLBackend("postgresql://test:test@localhost/test")

        assert backend.database_url == "postgresql://test:test@localhost/test"
        mock_create_engine.assert_called_once()
        mock_sessionmaker.assert_called_once()

    def test_supports_persistence(self):
        """Test persistence support."""
        with patch("mini_llm_chat.backends.postgresql.create_engine"):
            with patch("mini_llm_chat.backends.postgresql.sessionmaker"):
                backend = PostgreSQLBackend()
                assert backend.supports_persistence()

    def test_get_backend_info(self):
        """Test backend information."""
        with patch("mini_llm_chat.backends.postgresql.create_engine"):
            with patch("mini_llm_chat.backends.postgresql.sessionmaker"):
                backend = PostgreSQLBackend()
                info = backend.get_backend_info()
                assert info["name"] == "PostgreSQL"
                assert info["type"] == "postgresql"
                assert info["persistent"]
                assert "user_management" in info["features"]


class TestUserModel:
    """Test cases for the User model."""

    def test_user_creation(self):
        """Test user model creation."""
        user = User(
            id=1,
            username="testuser",
            email="test@test.com",
            hashed_password="hashed",
            role="user",
        )

        assert user.id == 1
        assert user.username == "testuser"
        assert user.email == "test@test.com"
        assert user.role == "user"
        assert user.is_active
        assert not user.is_admin()

    def test_admin_user(self):
        """Test admin user functionality."""
        user = User(
            id=1,
            username="admin",
            email="admin@test.com",
            hashed_password="hashed",
            role="admin",
        )

        assert user.is_admin()

    def test_password_operations(self):
        """Test password setting and verification."""
        user = User(
            id=1,
            username="testuser",
            email="test@test.com",
            hashed_password="",
            role="user",
        )

        # Set password
        user.set_password("testpassword")
        assert user.hashed_password != ""
        assert user.hashed_password != "testpassword"  # Should be hashed

        # Verify correct password
        assert user.verify_password("testpassword")

        # Verify incorrect password
        assert not user.verify_password("wrongpassword")

    def test_token_generation_and_verification(self):
        """Test JWT token generation and verification."""
        user = User(
            id=1,
            username="testuser",
            email="test@test.com",
            hashed_password="hashed",
            role="user",
        )

        # Generate token
        token = user.generate_token()
        assert token is not None
        assert isinstance(token, str)

        # Verify token
        payload = User.verify_token(token)
        assert payload is not None
        assert payload["user_id"] == 1
        assert payload["username"] == "testuser"
        assert payload["role"] == "user"

        # Verify invalid token
        payload = User.verify_token("invalid_token")
        assert payload is None


class TestConversationModel:
    """Test cases for the Conversation model."""

    def test_conversation_creation(self):
        """Test conversation model creation."""
        conversation = Conversation(id=1, user_id=1, title="Test Chat")

        assert conversation.id == 1
        assert conversation.user_id == 1
        assert conversation.title == "Test Chat"
        assert isinstance(conversation.created_at, datetime)
        assert isinstance(conversation.updated_at, datetime)


class TestMessageModel:
    """Test cases for the Message model."""

    def test_message_creation(self):
        """Test message model creation."""
        message = Message(
            id=1,
            conversation_id=1,
            role="user",
            content="Hello, world!",
            token_count=10,
        )

        assert message.id == 1
        assert message.conversation_id == 1
        assert message.role == "user"
        assert message.content == "Hello, world!"
        assert message.token_count == 10
        assert isinstance(message.created_at, datetime)
