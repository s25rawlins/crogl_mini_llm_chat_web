"""
Dependencies Module

This module provides FastAPI dependency injection functions for authentication,
rate limiting, and other common functionality across API endpoints.
"""

import logging
import os
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from mini_llm_chat.auth import AuthenticationError, get_user_by_token
from mini_llm_chat.backends.base import User
from mini_llm_chat.rate_limiter import SimpleRateLimiter

logger = logging.getLogger(__name__)

# Security scheme for JWT tokens
security = HTTPBearer()

# Global rate limiter instance
_rate_limiter: Optional[SimpleRateLimiter] = None


def get_rate_limiter() -> SimpleRateLimiter:
    """
    Get or create the global rate limiter instance.
    
    Returns:
        SimpleRateLimiter: Rate limiter instance
    """
    global _rate_limiter
    if _rate_limiter is None:
        max_calls = int(os.getenv("RATE_LIMIT_MAX_CALLS", "10"))
        time_window = int(os.getenv("RATE_LIMIT_TIME_WINDOW", "60"))
        _rate_limiter = SimpleRateLimiter(max_calls, time_window)
        logger.info(f"Rate limiter initialized: {max_calls} calls per {time_window} seconds")
    return _rate_limiter


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> User:
    """
    Get the current authenticated user from JWT token.
    
    Args:
        credentials: HTTP authorization credentials containing JWT token
        
    Returns:
        User: Authenticated user object
        
    Raises:
        HTTPException: If authentication fails
    """
    try:
        token = credentials.credentials
        user = get_user_by_token(token)
        
        if not user:
            logger.warning("Invalid or expired token provided")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        logger.debug(f"User authenticated: {user.username}")
        return user
        
    except AuthenticationError as e:
        logger.warning(f"Authentication failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        logger.error(f"Unexpected authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_admin_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Get the current user and verify admin privileges.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        User: Authenticated admin user
        
    Raises:
        HTTPException: If user is not an admin
    """
    if not current_user.is_admin():
        logger.warning(f"User {current_user.username} attempted admin action without privileges")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    
    return current_user


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[User]:
    """
    Get the current user if authenticated, otherwise return None.
    
    This is useful for endpoints that work for both authenticated and
    anonymous users but provide different functionality.
    
    Args:
        credentials: Optional HTTP authorization credentials
        
    Returns:
        Optional[User]: Authenticated user or None
    """
    if not credentials:
        return None
    
    try:
        token = credentials.credentials
        user = get_user_by_token(token)
        if user:
            logger.debug(f"Optional user authenticated: {user.username}")
        return user
    except Exception as e:
        logger.debug(f"Optional authentication failed: {e}")
        return None


def apply_rate_limit() -> None:
    """
    Apply rate limiting to the current request.
    
    This dependency can be used to enforce rate limits on API endpoints.
    
    Raises:
        HTTPException: If rate limit is exceeded
    """
    try:
        rate_limiter = get_rate_limiter()
        rate_limiter.acquire()
        logger.debug("Rate limit check passed")
    except Exception as e:
        logger.warning(f"Rate limit exceeded: {e}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later.",
            headers={"Retry-After": "60"}
        )


def get_openai_api_key() -> str:
    """
    Get the OpenAI API key from environment variables.
    
    Returns:
        str: OpenAI API key
        
    Raises:
        HTTPException: If API key is not configured
    """
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        logger.error("OpenAI API key not configured")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OpenAI API key not configured"
        )
    return api_key


def validate_conversation_access(user: User, conversation_id: int) -> bool:
    """
    Validate that a user has access to a specific conversation.
    
    Args:
        user: Current user
        conversation_id: ID of the conversation to check
        
    Returns:
        bool: True if user has access, False otherwise
    """
    # For now, we'll implement basic validation
    # In a more complex system, you might check conversation ownership
    # or shared access permissions
    
    try:
        from mini_llm_chat.database_manager import get_database_manager
        
        backend = get_database_manager().get_backend()
        
        # For PostgreSQL backend, we can check conversation ownership
        if hasattr(backend, '_get_session'):
            session = backend._get_session()
            try:
                from mini_llm_chat.backends.postgresql import SQLAlchemyConversation
                
                conversation = (
                    session.query(SQLAlchemyConversation)
                    .filter(
                        SQLAlchemyConversation.id == conversation_id,
                        SQLAlchemyConversation.user_id == user.id
                    )
                    .first()
                )
                return conversation is not None
            finally:
                session.close()
        
        # For in-memory backend, assume access is allowed
        # (since it's typically single-user)
        return True
        
    except Exception as e:
        logger.error(f"Error validating conversation access: {e}")
        return False


async def verify_conversation_access(
    conversation_id: int,
    current_user: User = Depends(get_current_user)
) -> int:
    """
    Dependency to verify user has access to a conversation.
    
    Args:
        conversation_id: ID of the conversation
        current_user: Current authenticated user
        
    Returns:
        int: Conversation ID if access is valid
        
    Raises:
        HTTPException: If user doesn't have access to the conversation
    """
    if not validate_conversation_access(current_user, conversation_id):
        logger.warning(
            f"User {current_user.username} attempted to access "
            f"conversation {conversation_id} without permission"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access to this conversation is forbidden"
        )
    
    return conversation_id
