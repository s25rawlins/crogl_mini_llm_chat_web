"""
Database Manager Module

This module provides a high-level interface for database operations using different backends.
It handles backend selection, initialization, and provides a unified API for the application.
"""

import logging
from typing import Optional

from .backends import DatabaseBackend, InMemoryBackend, PostgreSQLBackend

logger = logging.getLogger(__name__)


class DatabaseConnectionError(Exception):
    """Raised when database connection fails."""

    pass


class DatabaseManager:
    """High-level database manager that handles backend selection and operations."""

    def __init__(self, backend: Optional[DatabaseBackend] = None):
        """Initialize database manager with a specific backend."""
        self.backend = backend
        self._initialized = False

    def initialize_backend(
        self,
        backend_type: str = "auto",
        fallback_to_memory: bool = False,
        database_url: Optional[str] = None,
    ) -> DatabaseBackend:
        """
        Initialize database backend based on type and availability.

        Args:
            backend_type: Type of backend ("postgresql", "memory", or "auto")
            fallback_to_memory: Whether to fallback to memory if PostgreSQL fails
            database_url: Optional database URL for PostgreSQL

        Returns:
            DatabaseBackend: Initialized backend

        Raises:
            DatabaseConnectionError: If backend initialization fails
        """
        if self.backend and self._initialized:
            return self.backend

        if backend_type == "memory":
            logger.info("Initializing in-memory database backend")
            self.backend = InMemoryBackend()
        elif backend_type == "postgresql":
            logger.info("Initializing PostgreSQL database backend")
            try:
                self.backend = PostgreSQLBackend(database_url)
                # Perform comprehensive PostgreSQL system checks
                self.backend.ensure_postgresql_system_ready()
            except Exception as e:
                if fallback_to_memory:
                    logger.warning(f"PostgreSQL initialization failed: {e}")
                    logger.info("Falling back to in-memory backend")
                    self.backend = InMemoryBackend()
                else:
                    raise DatabaseConnectionError(
                        f"PostgreSQL initialization failed: {e}"
                    )
        elif backend_type == "auto":
            # Try PostgreSQL first, fallback to memory
            try:
                logger.info(
                    "Auto-detecting database backend (trying PostgreSQL first)"
                )
                self.backend = PostgreSQLBackend(database_url)
                # Perform comprehensive PostgreSQL system checks
                self.backend.ensure_postgresql_system_ready()
                logger.info("Successfully initialized PostgreSQL backend")
            except Exception as e:
                logger.warning(f"PostgreSQL not available: {e}")
                logger.info("Using in-memory backend")
                self.backend = InMemoryBackend()
        else:
            raise ValueError(f"Unknown backend type: {backend_type}")

        # Initialize the backend
        try:
            # For PostgreSQL backends, use smart initialization
            if hasattr(self.backend, "ensure_database_ready"):
                admin_needed = not self.backend.ensure_database_ready()
                if admin_needed:
                    logger.info("Database ready but no admin users found")
                    # We'll handle admin user creation in the CLI
            else:
                # For other backends, use traditional initialization
                self.backend.init_db()

            self._initialized = True
            backend_name = self.backend.get_backend_info()["name"]
            logger.info(f"Database backend initialized: {backend_name}")
            return self.backend
        except Exception as e:
            raise DatabaseConnectionError(f"Backend initialization failed: {e}")

    def get_backend(self) -> DatabaseBackend:
        """Get the current database backend."""
        if not self.backend or not self._initialized:
            raise RuntimeError("Database backend not initialized")
        return self.backend

    def get_backend_info(self) -> dict:
        """Get information about the current backend."""
        if not self.backend:
            return {"name": "None", "initialized": False}

        info = self.backend.get_backend_info()
        info["initialized"] = self._initialized
        return info

    def supports_persistence(self) -> bool:
        """Check if current backend supports persistence."""
        if not self.backend:
            return False
        return self.backend.supports_persistence()

    def prompt_for_fallback(self) -> bool:
        """Prompt user for fallback to in-memory mode."""
        try:
            response = (
                input(
                    "PostgreSQL database is not available. Would you like to use in-memory mode instead?\n"
                    "Note: In-memory mode has limited functionality and no data persistence.\n"
                    "Continue with in-memory mode? (y/N): "
                )
                .strip()
                .lower()
            )
            return response in ["y", "yes"]
        except (EOFError, KeyboardInterrupt):
            return False


# Global database manager instance
_db_manager = DatabaseManager()


def get_database_manager() -> DatabaseManager:
    """Get the global database manager instance."""
    return _db_manager


def initialize_database(
    backend_type: str = "auto",
    fallback_to_memory: bool = False,
    database_url: Optional[str] = None,
    interactive_fallback: bool = False,
) -> DatabaseBackend:
    """
    Initialize database with the specified backend.

    Args:
        backend_type: Type of backend to use
        fallback_to_memory: Whether to automatically fallback to memory
        database_url: Optional database URL
        interactive_fallback: Whether to prompt user for fallback

    Returns:
        DatabaseBackend: Initialized backend
    """
    manager = get_database_manager()

    try:
        return manager.initialize_backend(
            backend_type, fallback_to_memory, database_url
        )
    except DatabaseConnectionError as e:
        if interactive_fallback and backend_type in ["postgresql", "auto"]:
            if manager.prompt_for_fallback():
                logger.info("User chose to fallback to in-memory mode")
                return manager.initialize_backend("memory", False, database_url)
        raise e


# Convenience functions that delegate to the current backend
def init_db() -> None:
    """Initialize database tables."""
    backend = get_database_manager().get_backend()
    backend.init_db()


def create_admin_user(username: str, email: str, password: str) -> bool:
    """Create an admin user if it doesn't exist."""
    backend = get_database_manager().get_backend()
    return backend.create_admin_user(username, email, password)


def authenticate_user(username: str, password: str):
    """Authenticate user with username and password."""
    backend = get_database_manager().get_backend()
    return backend.authenticate_user(username, password)


def get_user_by_token(token: str):
    """Get user by JWT token."""
    backend = get_database_manager().get_backend()
    return backend.get_user_by_token(token)


def create_conversation(user_id: int, title: Optional[str] = None):
    """Create a new conversation for a user."""
    backend = get_database_manager().get_backend()
    return backend.create_conversation(user_id, title)


def add_message(
    conversation_id: int, role: str, content: str, token_count: Optional[int] = None
):
    """Add a message to a conversation."""
    backend = get_database_manager().get_backend()
    return backend.add_message(conversation_id, role, content, token_count)


def get_conversation_messages(conversation_id: int, limit: Optional[int] = None):
    """Get messages from a conversation."""
    backend = get_database_manager().get_backend()
    return backend.get_conversation_messages(conversation_id, limit)


def truncate_conversation_messages(conversation_id: int, max_messages: int) -> bool:
    """Truncate old messages from a conversation to stay within limits."""
    backend = get_database_manager().get_backend()
    return backend.truncate_conversation_messages(conversation_id, max_messages)


def get_session_user():
    """Get session user for in-memory backend."""
    backend = get_database_manager().get_backend()
    if hasattr(backend, "get_session_user"):
        return backend.get_session_user()
    return None
