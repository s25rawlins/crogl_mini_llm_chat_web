"""
Database Module

This module handles database connections, models, and operations for the Mini LLM Chat application.
It uses SQLAlchemy for ORM functionality and supports PostgreSQL as the primary database.
"""

import logging
import os
from datetime import UTC, datetime, timedelta
from typing import List, Optional

import bcrypt
import jwt
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://localhost:5432/mini_llm_chat")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# SQLAlchemy setup
Base = declarative_base()
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

logger = logging.getLogger(__name__)


class User(Base):
    """
    User model for authentication and authorization.

    Stores user credentials, roles, and metadata for the chat application.
    """

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default="user", nullable=False)  # 'admin' or 'user'
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC), nullable=False)
    last_login = Column(DateTime, nullable=True)

    # Relationship to conversations
    conversations = relationship("Conversation", back_populates="user")

    def set_password(self, password: str) -> None:
        """Hash and set the user's password."""
        salt = bcrypt.gensalt()
        self.hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt).decode(
            "utf-8"
        )

    def verify_password(self, password: str) -> bool:
        """Verify the user's password."""
        return bcrypt.checkpw(
            password.encode("utf-8"), self.hashed_password.encode("utf-8")
        )

    def is_admin(self) -> bool:
        """Check if user has admin role."""
        return self.role == "admin"

    def generate_token(self) -> str:
        """Generate JWT token for the user."""
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
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
            return None


class Conversation(Base):
    """
    Conversation model to store chat sessions.

    Each conversation belongs to a user and contains multiple messages.
    """

    __tablename__ = "conversations"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    title = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC), nullable=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )

    # Relationships
    user = relationship("User", back_populates="conversations")
    messages = relationship(
        "Message", back_populates="conversation", cascade="all, delete-orphan"
    )


class Message(Base):
    """
    Message model to store individual chat messages.

    Each message belongs to a conversation and has a role (user, assistant, system).
    """

    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    conversation_id = Column(Integer, ForeignKey("conversations.id"), nullable=False)
    role = Column(String(20), nullable=False)  # 'user', 'assistant', 'system'
    content = Column(Text, nullable=False)
    token_count = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC), nullable=False)

    # Relationship
    conversation = relationship("Conversation", back_populates="messages")


def get_db() -> Session:
    """Get database session."""
    db = SessionLocal()
    try:
        return db
    finally:
        pass  # Session will be closed by caller


def init_db() -> None:
    """Initialize database tables."""
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise


def create_admin_user(username: str, email: str, password: str) -> bool:
    """Create an admin user if it doesn't exist."""
    db = get_db()
    try:
        # Check if admin user already exists
        existing_user = db.query(User).filter(User.username == username).first()
        if existing_user:
            logger.info(f"Admin user '{username}' already exists")
            return False

        # Create admin user
        admin_user = User(username=username, email=email, role="admin", is_active=True)
        admin_user.set_password(password)

        db.add(admin_user)
        db.commit()
        logger.info(f"Admin user '{username}' created successfully")
        return True
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create admin user: {e}")
        return False
    finally:
        db.close()


def authenticate_user(username: str, password: str) -> Optional[User]:
    """Authenticate user with username and password."""
    db = get_db()
    try:
        user = (
            db.query(User)
            .filter(User.username == username, User.is_active.is_(True))
            .first()
        )

        if user and user.verify_password(password):
            # Update last login
            user.last_login = datetime.now(UTC)
            db.commit()
            # Refresh the user object to ensure all attributes are loaded
            db.refresh(user)
            # Expunge the user from the session so it can be used after session closes
            db.expunge(user)
            return user
        return None
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return None
    finally:
        db.close()


def get_user_by_token(token: str) -> Optional[User]:
    """Get user by JWT token."""
    payload = User.verify_token(token)
    if not payload:
        return None

    db = get_db()
    try:
        user = (
            db.query(User)
            .filter(User.id == payload["user_id"], User.is_active.is_(True))
            .first()
        )
        if user:
            # Refresh the user object to ensure all attributes are loaded
            db.refresh(user)
            # Expunge the user from the session so it can be used after session closes
            db.expunge(user)
        return user
    except Exception as e:
        logger.error(f"Error getting user by token: {e}")
        return None
    finally:
        db.close()


def create_conversation(
    user_id: int, title: Optional[str] = None
) -> Optional[Conversation]:
    """Create a new conversation for a user."""
    db = get_db()
    try:
        conversation = Conversation(
            user_id=user_id,
            title=title or f"Chat {datetime.now(UTC).strftime('%Y-%m-%d %H:%M')}",
        )
        db.add(conversation)
        db.commit()
        db.refresh(conversation)
        return conversation
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create conversation: {e}")
        return None
    finally:
        db.close()


def add_message(
    conversation_id: int, role: str, content: str, token_count: Optional[int] = None
) -> Optional[Message]:
    """Add a message to a conversation."""
    db = get_db()
    try:
        message = Message(
            conversation_id=conversation_id,
            role=role,
            content=content,
            token_count=token_count,
        )
        db.add(message)
        db.commit()
        db.refresh(message)
        return message
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to add message: {e}")
        return None
    finally:
        db.close()


def get_conversation_messages(
    conversation_id: int, limit: Optional[int] = None
) -> List[Message]:
    """Get messages from a conversation."""
    db = get_db()
    try:
        query = (
            db.query(Message)
            .filter(Message.conversation_id == conversation_id)
            .order_by(Message.created_at)
        )
        if limit:
            query = query.limit(limit)
        return query.all()
    except Exception as e:
        logger.error(f"Failed to get conversation messages: {e}")
        return []
    finally:
        db.close()


def truncate_conversation_messages(conversation_id: int, max_messages: int) -> bool:
    """Truncate old messages from a conversation to stay within limits."""
    db = get_db()
    try:
        # Get total message count
        total_messages = (
            db.query(Message).filter(Message.conversation_id == conversation_id).count()
        )

        if total_messages <= max_messages:
            return True  # No truncation needed

        # Keep the system message (first message) and the most recent messages
        messages_to_delete = total_messages - max_messages

        # Get messages to delete (excluding system messages)
        messages_to_remove = (
            db.query(Message)
            .filter(
                Message.conversation_id == conversation_id, Message.role != "system"
            )
            .order_by(Message.created_at)
            .limit(messages_to_delete)
            .all()
        )

        # Delete old messages
        for message in messages_to_remove:
            db.delete(message)

        db.commit()
        logger.info(
            f"Truncated {len(messages_to_remove)} messages from conversation {conversation_id}"
        )
        return True
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to truncate conversation messages: {e}")
        return False
    finally:
        db.close()
