"""
Base Database Backend Interface

This module defines the abstract interface that all database backends must implement.
It provides a consistent API for database operations regardless of the underlying storage.
"""

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import List, Optional


class DatabaseBackend(ABC):
    """Abstract base class for database backends."""

    @abstractmethod
    def init_db(self) -> None:
        """Initialize database tables/structures."""
        pass

    @abstractmethod
    def create_admin_user(self, username: str, email: str, password: str) -> bool:
        """Create an admin user if it doesn't exist."""
        pass

    @abstractmethod
    def authenticate_user(self, username: str, password: str) -> Optional["User"]:
        """Authenticate user with username and password."""
        pass

    @abstractmethod
    def get_user_by_token(self, token: str) -> Optional["User"]:
        """Get user by JWT token."""
        pass

    @abstractmethod
    def create_conversation(
        self, user_id: int, title: Optional[str] = None
    ) -> Optional["Conversation"]:
        """Create a new conversation for a user."""
        pass

    @abstractmethod
    def add_message(
        self,
        conversation_id: int,
        role: str,
        content: str,
        token_count: Optional[int] = None,
    ) -> Optional["Message"]:
        """Add a message to a conversation."""
        pass

    @abstractmethod
    def get_conversation_messages(
        self, conversation_id: int, limit: Optional[int] = None
    ) -> List["Message"]:
        """Get messages from a conversation."""
        pass

    @abstractmethod
    def truncate_conversation_messages(
        self, conversation_id: int, max_messages: int
    ) -> bool:
        """Truncate old messages from a conversation to stay within limits."""
        pass

    @abstractmethod
    def supports_persistence(self) -> bool:
        """Return True if this backend supports data persistence across sessions."""
        pass

    @abstractmethod
    def get_backend_info(self) -> dict:
        """Return information about this backend."""
        pass


class User:
    """User model interface that all backends must implement."""

    def __init__(
        self,
        id: int,
        username: str,
        email: str,
        hashed_password: Optional[str] = None,
        role: str = "user",
        is_active: bool = True,
        created_at: Optional[datetime] = None,
        last_login: Optional[datetime] = None,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        oauth_provider: Optional[str] = None,
        oauth_id: Optional[str] = None,
        email_verified: bool = False,
        password_reset_token: Optional[str] = None,
        password_reset_expires: Optional[datetime] = None,
    ):
        self.id = id
        self.username = username
        self.email = email
        self.hashed_password = hashed_password
        self.role = role
        self.is_active = is_active
        self.created_at = created_at or datetime.now(UTC)
        self.last_login = last_login
        self.first_name = first_name
        self.last_name = last_name
        self.oauth_provider = oauth_provider
        self.oauth_id = oauth_id
        self.email_verified = email_verified
        self.password_reset_token = password_reset_token
        self.password_reset_expires = password_reset_expires

    def set_password(self, password: str) -> None:
        """Hash and set the user's password."""
        import bcrypt

        salt = bcrypt.gensalt()
        self.hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt).decode(
            "utf-8"
        )

    def verify_password(self, password: str) -> bool:
        """Verify the user's password."""
        import bcrypt

        return bcrypt.checkpw(
            password.encode("utf-8"), self.hashed_password.encode("utf-8")
        )

    def is_admin(self) -> bool:
        """Check if user has admin role."""
        return self.role == "admin"

    def generate_token(self) -> str:
        """Generate JWT token for the user."""
        import os
        from datetime import timedelta

        import jwt

        JWT_SECRET_KEY = os.getenv(
            "JWT_SECRET_KEY", "your-secret-key-change-in-production"
        )
        JWT_ALGORITHM = "HS256"
        JWT_EXPIRATION_HOURS = 24

        payload = {
            "user_id": self.id,
            "username": self.username,
            "role": self.role,
            "exp": datetime.now(UTC) + timedelta(hours=JWT_EXPIRATION_HOURS),
        }
        return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    @staticmethod
    def verify_token(token: str) -> Optional[dict]:
        """Verify and decode JWT token."""
        import logging
        import os

        import jwt

        JWT_SECRET_KEY = os.getenv(
            "JWT_SECRET_KEY", "your-secret-key-change-in-production"
        )
        JWT_ALGORITHM = "HS256"
        logger = logging.getLogger(__name__)

        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
            return None


class Conversation:
    """Conversation model interface that all backends must implement."""

    def __init__(
        self,
        id: int,
        user_id: int,
        title: Optional[str] = None,
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None,
    ):
        self.id = id
        self.user_id = user_id
        self.title = title
        self.created_at = created_at or datetime.now(UTC)
        self.updated_at = updated_at or datetime.now(UTC)


class Message:
    """Message model interface that all backends must implement."""

    def __init__(
        self,
        id: int,
        conversation_id: int,
        role: str,
        content: str,
        token_count: Optional[int] = None,
        created_at: Optional[datetime] = None,
    ):
        self.id = id
        self.conversation_id = conversation_id
        self.role = role
        self.content = content
        self.token_count = token_count
        self.created_at = created_at or datetime.now(UTC)
