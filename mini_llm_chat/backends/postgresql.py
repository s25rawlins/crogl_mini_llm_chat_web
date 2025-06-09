"""
PostgreSQL Database Backend

This module implements the PostgreSQL backend for the Mini LLM Chat application.
It wraps the existing SQLAlchemy-based database functionality and includes
comprehensive PostgreSQL system initialization and management.
"""

import logging
import os
from datetime import datetime
from typing import List, Optional

import bcrypt
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

from .base import Conversation as BaseConversation
from .base import (
    DatabaseBackend,
)
from .base import Message as BaseMessage
from .base import User as BaseUser
from ..utils.postgresql_utils import ensure_postgresql_ready, get_postgresql_status

logger = logging.getLogger(__name__)

# Database configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# SQLAlchemy setup
Base = declarative_base()


class SQLAlchemyUser(Base):
    """SQLAlchemy User model for PostgreSQL backend."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    first_name = Column(String(50), nullable=True)
    last_name = Column(String(50), nullable=True)
    hashed_password = Column(String(255), nullable=True)  # Nullable for OAuth users
    role = Column(String(20), default="user", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    oauth_provider = Column(String(50), nullable=True)  # 'google', etc.
    oauth_id = Column(String(100), nullable=True)  # OAuth provider user ID
    email_verified = Column(Boolean, default=False, nullable=False)
    password_reset_token = Column(String(255), nullable=True)
    password_reset_expires = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)

    conversations = relationship("SQLAlchemyConversation", back_populates="user")


class SQLAlchemyConversation(Base):
    """SQLAlchemy Conversation model for PostgreSQL backend."""

    __tablename__ = "conversations"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    title = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    user = relationship("SQLAlchemyUser", back_populates="conversations")
    messages = relationship(
        "SQLAlchemyMessage", back_populates="conversation", cascade="all, delete-orphan"
    )


class SQLAlchemyMessage(Base):
    """SQLAlchemy Message model for PostgreSQL backend."""

    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    conversation_id = Column(Integer, ForeignKey("conversations.id"), nullable=False)
    role = Column(String(20), nullable=False)
    content = Column(Text, nullable=False)
    token_count = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    conversation = relationship("SQLAlchemyConversation", back_populates="messages")


class PostgreSQLBackend(DatabaseBackend):
    """PostgreSQL database backend implementation."""

    def __init__(self, database_url: Optional[str] = None):
        """Initialize PostgreSQL backend."""
        self.database_url = database_url or os.getenv(
            "DATABASE_URL", "postgresql://localhost:5432/mini_llm_chat"
        )

        try:
            self.engine = create_engine(self.database_url)
            self.SessionLocal = sessionmaker(
                autocommit=False, autoflush=False, bind=self.engine
            )
            logger.info(f"PostgreSQL backend initialized with URL: {self.database_url}")
        except Exception as e:
            logger.error(f"Failed to initialize PostgreSQL backend: {e}")
            raise

    def ensure_postgresql_system_ready(self) -> bool:
        """
        Ensure PostgreSQL system is ready for use.
        
        This method performs comprehensive system-level checks:
        1. Verify PostgreSQL is installed
        2. Check if PostgreSQL service is running, start if needed
        3. Verify database exists, create if needed
        4. Test database connection
        
        Returns:
            bool: True if PostgreSQL system is ready, False otherwise
            
        Raises:
            Exception: If there are unrecoverable errors
        """
        try:
            logger.info("Performing comprehensive PostgreSQL system checks...")
            
            # Get system status first
            status = get_postgresql_status()
            
            if not status["installed"]:
                logger.error("PostgreSQL is not installed on this system")
                raise Exception(
                    "PostgreSQL is not installed. Please install PostgreSQL and try again.\n"
                    "Installation guides:\n"
                    "  Ubuntu/Debian: sudo apt-get install postgresql postgresql-contrib\n"
                    "  CentOS/RHEL: sudo yum install postgresql-server postgresql-contrib\n"
                    "  macOS: brew install postgresql\n"
                    "  Windows: Download from https://www.postgresql.org/download/windows/"
                )
            
            logger.info(f"PostgreSQL installation found: {status.get('version', 'Unknown version')}")
            
            # Use the comprehensive system readiness check
            success, error_message = ensure_postgresql_ready(self.database_url)
            
            if not success:
                logger.error(f"PostgreSQL system check failed: {error_message}")
                raise Exception(error_message)
            
            logger.info("PostgreSQL system is ready")
            return True
            
        except Exception as e:
            logger.error(f"PostgreSQL system readiness check failed: {e}")
            raise

    def _get_session(self) -> Session:
        """Get database session."""
        return self.SessionLocal()

    def _convert_user(self, sqlalchemy_user: SQLAlchemyUser) -> BaseUser:
        """Convert SQLAlchemy user to base user model."""
        return BaseUser(
            id=sqlalchemy_user.id,
            username=sqlalchemy_user.username,
            email=sqlalchemy_user.email,
            hashed_password=sqlalchemy_user.hashed_password,
            role=sqlalchemy_user.role,
            is_active=sqlalchemy_user.is_active,
            created_at=sqlalchemy_user.created_at,
            last_login=sqlalchemy_user.last_login,
            first_name=sqlalchemy_user.first_name,
            last_name=sqlalchemy_user.last_name,
            oauth_provider=sqlalchemy_user.oauth_provider,
            oauth_id=sqlalchemy_user.oauth_id,
            email_verified=sqlalchemy_user.email_verified,
            password_reset_token=sqlalchemy_user.password_reset_token,
            password_reset_expires=sqlalchemy_user.password_reset_expires,
        )

    def _convert_conversation(
        self, sqlalchemy_conv: SQLAlchemyConversation
    ) -> BaseConversation:
        """Convert SQLAlchemy conversation to base conversation model."""
        return BaseConversation(
            id=sqlalchemy_conv.id,
            user_id=sqlalchemy_conv.user_id,
            title=sqlalchemy_conv.title,
            created_at=sqlalchemy_conv.created_at,
            updated_at=sqlalchemy_conv.updated_at,
        )

    def _convert_message(self, sqlalchemy_msg: SQLAlchemyMessage) -> BaseMessage:
        """Convert SQLAlchemy message to base message model."""
        return BaseMessage(
            id=sqlalchemy_msg.id,
            conversation_id=sqlalchemy_msg.conversation_id,
            role=sqlalchemy_msg.role,
            content=sqlalchemy_msg.content,
            token_count=sqlalchemy_msg.token_count,
            created_at=sqlalchemy_msg.created_at,
        )

    def init_db(self) -> None:
        """Initialize database tables."""
        try:
            Base.metadata.create_all(bind=self.engine)
            logger.info("PostgreSQL database tables created successfully")
        except Exception as e:
            logger.error(f"Failed to create PostgreSQL database tables: {e}")
            raise

    def is_database_initialized(self) -> bool:
        """Check if database tables exist and are properly initialized."""
        try:
            from sqlalchemy import inspect

            inspector = inspect(self.engine)

            # Check if all required tables exist
            required_tables = {"users", "conversations", "messages"}
            existing_tables = set(inspector.get_table_names())

            tables_exist = required_tables.issubset(existing_tables)

            if tables_exist:
                logger.debug("Database tables exist")
                return True
            else:
                missing_tables = required_tables - existing_tables
                logger.debug(f"Missing database tables: {missing_tables}")
                return False

        except Exception as e:
            logger.warning(f"Could not check database initialization status: {e}")
            return False

    def has_admin_users(self) -> bool:
        """Check if any admin users exist in the database."""
        try:
            session = self._get_session()
            try:
                admin_count = (
                    session.query(SQLAlchemyUser)
                    .filter(
                        SQLAlchemyUser.role == "admin",
                        SQLAlchemyUser.is_active.is_(True),
                    )
                    .count()
                )
                return admin_count > 0
            finally:
                session.close()
        except Exception as e:
            logger.warning(f"Could not check for admin users: {e}")
            return False

    def ensure_database_ready(self) -> bool:
        """Ensure database is initialized and has at least one admin user."""
        try:
            # Check if database is initialized
            if not self.is_database_initialized():
                logger.info("Database not initialized, creating tables...")
                self.init_db()
                logger.info("Database tables created successfully")
            else:
                logger.debug("Database tables already exist")

            # Check if admin users exist
            if not self.has_admin_users():
                logger.info(
                    "No admin users found, prompting for admin user creation..."
                )
                return False  # Caller should handle admin user creation
            else:
                logger.debug("Admin users exist")

            return True

        except Exception as e:
            logger.error(f"Failed to ensure database is ready: {e}")
            raise

    def create_admin_user(self, username: str, email: str, password: str) -> bool:
        """Create an admin user if it doesn't exist."""
        session = self._get_session()
        try:
            # Check if admin user already exists
            existing_user = (
                session.query(SQLAlchemyUser)
                .filter(SQLAlchemyUser.username == username)
                .first()
            )
            if existing_user:
                logger.info(f"Admin user '{username}' already exists")
                return False

            # Create admin user
            admin_user = SQLAlchemyUser(
                username=username, email=email, role="admin", is_active=True
            )

            # Hash password
            salt = bcrypt.gensalt()
            admin_user.hashed_password = bcrypt.hashpw(
                password.encode("utf-8"), salt
            ).decode("utf-8")

            session.add(admin_user)
            session.commit()
            logger.info(f"Admin user '{username}' created successfully")
            return True
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to create admin user: {e}")
            return False
        finally:
            session.close()

    def authenticate_user(self, username: str, password: str) -> Optional[BaseUser]:
        """Authenticate user with username and password."""
        session = self._get_session()
        try:
            user = (
                session.query(SQLAlchemyUser)
                .filter(
                    SQLAlchemyUser.username == username,
                    SQLAlchemyUser.is_active.is_(True),
                )
                .first()
            )

            if user and bcrypt.checkpw(
                password.encode("utf-8"), user.hashed_password.encode("utf-8")
            ):
                # Update last login
                user.last_login = datetime.utcnow()
                session.commit()
                session.refresh(user)
                return self._convert_user(user)
            return None
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return None
        finally:
            session.close()

    def get_user_by_token(self, token: str) -> Optional[BaseUser]:
        """Get user by JWT token."""
        payload = BaseUser.verify_token(token)
        if not payload:
            return None

        session = self._get_session()
        try:
            user = (
                session.query(SQLAlchemyUser)
                .filter(
                    SQLAlchemyUser.id == payload["user_id"],
                    SQLAlchemyUser.is_active.is_(True),
                )
                .first()
            )
            if user:
                return self._convert_user(user)
            return None
        except Exception as e:
            logger.error(f"Error getting user by token: {e}")
            return None
        finally:
            session.close()

    def create_conversation(
        self, user_id: int, title: Optional[str] = None
    ) -> Optional[BaseConversation]:
        """Create a new conversation for a user."""
        session = self._get_session()
        try:
            conversation = SQLAlchemyConversation(
                user_id=user_id,
                title=title or f"Chat {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}",
            )
            session.add(conversation)
            session.commit()
            session.refresh(conversation)
            return self._convert_conversation(conversation)
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to create conversation: {e}")
            return None
        finally:
            session.close()

    def add_message(
        self,
        conversation_id: int,
        role: str,
        content: str,
        token_count: Optional[int] = None,
    ) -> Optional[BaseMessage]:
        """Add a message to a conversation."""
        session = self._get_session()
        try:
            message = SQLAlchemyMessage(
                conversation_id=conversation_id,
                role=role,
                content=content,
                token_count=token_count,
            )
            session.add(message)
            session.commit()
            session.refresh(message)
            return self._convert_message(message)
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to add message: {e}")
            return None
        finally:
            session.close()

    def get_conversation_messages(
        self, conversation_id: int, limit: Optional[int] = None
    ) -> List[BaseMessage]:
        """Get messages from a conversation."""
        session = self._get_session()
        try:
            query = (
                session.query(SQLAlchemyMessage)
                .filter(SQLAlchemyMessage.conversation_id == conversation_id)
                .order_by(SQLAlchemyMessage.created_at)
            )
            if limit:
                query = query.limit(limit)

            messages = query.all()
            return [self._convert_message(msg) for msg in messages]
        except Exception as e:
            logger.error(f"Failed to get conversation messages: {e}")
            return []
        finally:
            session.close()

    def truncate_conversation_messages(
        self, conversation_id: int, max_messages: int
    ) -> bool:
        """Truncate old messages from a conversation to stay within limits."""
        session = self._get_session()
        try:
            # Get total message count
            total_messages = (
                session.query(SQLAlchemyMessage)
                .filter(SQLAlchemyMessage.conversation_id == conversation_id)
                .count()
            )

            if total_messages <= max_messages:
                return True  # No truncation needed

            # Keep the system message (first message) and the most recent messages
            messages_to_delete = total_messages - max_messages

            # Get messages to delete (excluding system messages)
            messages_to_remove = (
                session.query(SQLAlchemyMessage)
                .filter(
                    SQLAlchemyMessage.conversation_id == conversation_id,
                    SQLAlchemyMessage.role != "system",
                )
                .order_by(SQLAlchemyMessage.created_at)
                .limit(messages_to_delete)
                .all()
            )

            # Delete old messages
            for message in messages_to_remove:
                session.delete(message)

            session.commit()
            logger.info(
                f"Truncated {len(messages_to_remove)} messages from conversation {conversation_id}"
            )
            return True
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to truncate conversation messages: {e}")
            return False
        finally:
            session.close()

    def supports_persistence(self) -> bool:
        """Return True if this backend supports data persistence across sessions."""
        return True

    def get_backend_info(self) -> dict:
        """Return information about this backend."""
        return {
            "name": "PostgreSQL",
            "type": "postgresql",
            "persistent": True,
            "features": [
                "user_management",
                "conversation_history",
                "role_based_access",
                "admin_functions",
                "data_persistence",
            ],
            "database_url": (
                self.database_url.split("@")[-1]
                if "@" in self.database_url
                else self.database_url
            ),
        }
