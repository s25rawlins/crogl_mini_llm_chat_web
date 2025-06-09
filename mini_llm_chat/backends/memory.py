"""
In-Memory Database Backend

This module implements an in-memory database backend for the Mini LLM Chat application.
It provides basic functionality without requiring external database dependencies.
Data is not persisted between application sessions.
"""

import logging
from datetime import UTC, datetime
from typing import Dict, List, Optional

from .base import Conversation as BaseConversation
from .base import (
    DatabaseBackend,
)
from .base import Message as BaseMessage
from .base import User as BaseUser

logger = logging.getLogger(__name__)


class InMemoryBackend(DatabaseBackend):
    """In-memory database backend implementation."""

    def __init__(self):
        """Initialize in-memory backend."""
        self.users: Dict[int, BaseUser] = {}
        self.conversations: Dict[int, BaseConversation] = {}
        self.messages: Dict[int, BaseMessage] = {}
        self.username_to_id: Dict[str, int] = {}

        # ID counters
        self._next_user_id = 1
        self._next_conversation_id = 1
        self._next_message_id = 1

        # Session storage for temporary users
        self.session_users: Dict[str, BaseUser] = {}

        logger.info("In-memory backend initialized")

    def init_db(self) -> None:
        """Initialize database tables/structures."""
        # Create a default session user for immediate use
        session_user = BaseUser(
            id=self._next_user_id,
            username="session_user",
            email="session@localhost",
            hashed_password="",  # No password needed for session user
            role="user",
            is_active=True,
            created_at=datetime.now(UTC),
        )

        self.users[session_user.id] = session_user
        self.username_to_id[session_user.username] = session_user.id
        self._next_user_id += 1

        logger.info("In-memory database structures initialized with session user")

    def create_admin_user(self, username: str, email: str, password: str) -> bool:
        """Create an admin user if it doesn't exist."""
        # Check if user already exists
        if username in self.username_to_id:
            logger.info(f"User '{username}' already exists")
            return False

        # Create admin user
        admin_user = BaseUser(
            id=self._next_user_id,
            username=username,
            email=email,
            hashed_password="",  # Will be set by set_password
            role="admin",
            is_active=True,
            created_at=datetime.now(UTC),
        )

        admin_user.set_password(password)

        self.users[admin_user.id] = admin_user
        self.username_to_id[username] = admin_user.id
        self._next_user_id += 1

        logger.info(f"Admin user '{username}' created successfully")
        return True

    def authenticate_user(self, username: str, password: str) -> Optional[BaseUser]:
        """Authenticate user with username and password."""
        try:
            user_id = self.username_to_id.get(username)
            if not user_id:
                return None

            user = self.users.get(user_id)
            if not user or not user.is_active:
                return None

            # For session user, allow any password
            if username == "session_user":
                user.last_login = datetime.now(UTC)
                return user

            # For regular users, verify password
            if user.verify_password(password):
                user.last_login = datetime.now(UTC)
                return user

            return None
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return None

    def get_user_by_token(self, token: str) -> Optional[BaseUser]:
        """Get user by JWT token."""
        payload = BaseUser.verify_token(token)
        if not payload:
            return None

        try:
            user_id = payload["user_id"]
            user = self.users.get(user_id)
            if user and user.is_active:
                return user
            return None
        except Exception as e:
            logger.error(f"Error getting user by token: {e}")
            return None

    def create_conversation(
        self, user_id: int, title: Optional[str] = None
    ) -> Optional[BaseConversation]:
        """Create a new conversation for a user."""
        try:
            # Verify user exists
            if user_id not in self.users:
                logger.error(f"User {user_id} not found")
                return None

            conversation = BaseConversation(
                id=self._next_conversation_id,
                user_id=user_id,
                title=title or f"Chat {datetime.now(UTC).strftime('%Y-%m-%d %H:%M')}",
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )

            self.conversations[conversation.id] = conversation
            self._next_conversation_id += 1

            logger.debug(f"Created conversation {conversation.id} for user {user_id}")
            return conversation
        except Exception as e:
            logger.error(f"Failed to create conversation: {e}")
            return None

    def add_message(
        self,
        conversation_id: int,
        role: str,
        content: str,
        token_count: Optional[int] = None,
    ) -> Optional[BaseMessage]:
        """Add a message to a conversation."""
        try:
            # Verify conversation exists
            if conversation_id not in self.conversations:
                logger.error(f"Conversation {conversation_id} not found")
                return None

            message = BaseMessage(
                id=self._next_message_id,
                conversation_id=conversation_id,
                role=role,
                content=content,
                token_count=token_count,
                created_at=datetime.now(UTC),
            )

            self.messages[message.id] = message
            self._next_message_id += 1

            # Update conversation timestamp
            conversation = self.conversations[conversation_id]
            conversation.updated_at = datetime.now(UTC)

            logger.debug(
                f"Added message {message.id} to conversation {conversation_id}"
            )
            return message
        except Exception as e:
            logger.error(f"Failed to add message: {e}")
            return None

    def get_conversation_messages(
        self, conversation_id: int, limit: Optional[int] = None
    ) -> List[BaseMessage]:
        """Get messages from a conversation."""
        try:
            # Get all messages for this conversation
            conversation_messages = [
                msg
                for msg in self.messages.values()
                if msg.conversation_id == conversation_id
            ]

            # Sort by creation time
            conversation_messages.sort(key=lambda x: x.created_at)

            # Apply limit if specified
            if limit:
                conversation_messages = conversation_messages[:limit]

            return conversation_messages
        except Exception as e:
            logger.error(f"Failed to get conversation messages: {e}")
            return []

    def truncate_conversation_messages(
        self, conversation_id: int, max_messages: int
    ) -> bool:
        """Truncate old messages from a conversation to stay within limits."""
        try:
            # Get all messages for this conversation
            conversation_messages = [
                msg
                for msg in self.messages.values()
                if msg.conversation_id == conversation_id
            ]

            if len(conversation_messages) <= max_messages:
                return True  # No truncation needed

            # Sort by creation time
            conversation_messages.sort(key=lambda x: x.created_at)

            # Keep system message (first) and most recent messages
            system_messages = [
                msg for msg in conversation_messages if msg.role == "system"
            ]
            non_system_messages = [
                msg for msg in conversation_messages if msg.role != "system"
            ]

            # Calculate how many non-system messages to delete
            total_to_keep = max_messages - len(system_messages)
            if total_to_keep > 0 and len(non_system_messages) > total_to_keep:
                messages_to_delete = non_system_messages[:-total_to_keep]

                # Delete old messages
                for msg in messages_to_delete:
                    del self.messages[msg.id]

                logger.info(
                    f"Truncated {len(messages_to_delete)} messages "
                    f"from conversation {conversation_id}"
                )

            return True
        except Exception as e:
            logger.error(f"Failed to truncate conversation messages: {e}")
            return False

    def supports_persistence(self) -> bool:
        """Return True if this backend supports data persistence across sessions."""
        return False

    def get_backend_info(self) -> dict:
        """Return information about this backend."""
        return {
            "name": "In-Memory",
            "type": "memory",
            "persistent": False,
            "features": [
                "basic_chat",
                "session_auth",
                "temporary_conversations",
                "rate_limiting",
            ],
            "limitations": [
                "no_persistence",
                "no_user_management",
                "session_only",
                "no_admin_functions",
            ],
            "stats": {
                "users": len(self.users),
                "conversations": len(self.conversations),
                "messages": len(self.messages),
            },
        }

    def get_session_user(self) -> Optional[BaseUser]:
        """Get the default session user for immediate use."""
        session_user_id = self.username_to_id.get("session_user")
        if session_user_id:
            return self.users.get(session_user_id)
        return None

    def create_session_user(self, session_id: str) -> BaseUser:
        """Create a temporary session user."""
        session_user = BaseUser(
            id=self._next_user_id,
            username=f"session_{session_id}",
            email=f"session_{session_id}@localhost",
            hashed_password="",
            role="user",
            is_active=True,
            created_at=datetime.now(UTC),
        )

        self.users[session_user.id] = session_user
        self.username_to_id[session_user.username] = session_user.id
        self.session_users[session_id] = session_user
        self._next_user_id += 1

        logger.info(f"Created session user for session {session_id}")
        return session_user

    def cleanup_session(self, session_id: str) -> bool:
        """Clean up session data."""
        try:
            if session_id in self.session_users:
                user = self.session_users[session_id]

                # Remove user's conversations and messages
                user_conversations = [
                    conv
                    for conv in self.conversations.values()
                    if conv.user_id == user.id
                ]

                for conv in user_conversations:
                    # Remove messages
                    conv_messages = [
                        msg
                        for msg in self.messages.values()
                        if msg.conversation_id == conv.id
                    ]
                    for msg in conv_messages:
                        del self.messages[msg.id]

                    # Remove conversation
                    del self.conversations[conv.id]

                # Remove user
                del self.username_to_id[user.username]
                del self.users[user.id]
                del self.session_users[session_id]

                logger.info(f"Cleaned up session {session_id}")
                return True
        except Exception as e:
            logger.error(f"Failed to cleanup session {session_id}: {e}")
            return False
