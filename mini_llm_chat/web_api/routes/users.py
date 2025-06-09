"""
Users Routes

This module contains FastAPI routes for user management,
including user profiles and admin functionality.
"""

import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status

from mini_llm_chat.backends.base import User
from mini_llm_chat.database_manager import get_database_manager
from mini_llm_chat.web_api.dependencies import get_current_admin_user, get_current_user
from mini_llm_chat.web_api.models.auth import UserResponse
from mini_llm_chat.web_api.models.chat import ConversationStatsResponse
from mini_llm_chat.web_api.models.common import PaginationParams, PaginatedResponse

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/me/stats", response_model=ConversationStatsResponse)
async def get_user_stats(
    current_user: User = Depends(get_current_user)
) -> ConversationStatsResponse:
    """
    Get statistics for the current user.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        ConversationStatsResponse: User statistics
    """
    try:
        backend = get_database_manager().get_backend()
        
        if hasattr(backend, '_get_session'):
            session = backend._get_session()
            try:
                from mini_llm_chat.backends.postgresql import SQLAlchemyConversation, SQLAlchemyMessage
                
                # Count conversations
                total_conversations = (
                    session.query(SQLAlchemyConversation)
                    .filter(SQLAlchemyConversation.user_id == current_user.id)
                    .count()
                )
                
                # Count messages
                total_messages = (
                    session.query(SQLAlchemyMessage)
                    .join(SQLAlchemyConversation)
                    .filter(SQLAlchemyConversation.user_id == current_user.id)
                    .count()
                )
                
                # Sum tokens
                total_tokens_result = (
                    session.query(session.query(SQLAlchemyMessage.token_count).label('sum'))
                    .join(SQLAlchemyConversation)
                    .filter(SQLAlchemyConversation.user_id == current_user.id)
                    .filter(SQLAlchemyMessage.token_count.isnot(None))
                    .scalar()
                )
                total_tokens = total_tokens_result if total_tokens_result else 0
                
                # Get most recent conversation
                most_recent = (
                    session.query(SQLAlchemyConversation.updated_at)
                    .filter(SQLAlchemyConversation.user_id == current_user.id)
                    .order_by(SQLAlchemyConversation.updated_at.desc())
                    .first()
                )
                most_recent_conversation = most_recent[0] if most_recent else None
                
            finally:
                session.close()
        else:
            # For in-memory backend, return minimal stats
            total_conversations = 0
            total_messages = 0
            total_tokens = 0
            most_recent_conversation = None
        
        return ConversationStatsResponse(
            total_conversations=total_conversations,
            total_messages=total_messages,
            total_tokens=total_tokens,
            most_recent_conversation=most_recent_conversation
        )
        
    except Exception as e:
        logger.error(f"Error getting stats for user {current_user.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user statistics"
        )


@router.get("/", response_model=PaginatedResponse[UserResponse])
async def list_users(
    pagination: PaginationParams = Depends(),
    current_user: User = Depends(get_current_admin_user)
) -> PaginatedResponse[UserResponse]:
    """
    List all users (admin only).
    
    Args:
        pagination: Pagination parameters
        current_user: Current authenticated admin user
        
    Returns:
        PaginatedResponse[UserResponse]: Paginated list of users
    """
    try:
        backend = get_database_manager().get_backend()
        
        if hasattr(backend, '_get_session'):
            session = backend._get_session()
            try:
                from mini_llm_chat.backends.postgresql import SQLAlchemyUser
                
                # Get total count
                total = session.query(SQLAlchemyUser).count()
                
                # Get users for current page
                db_users = (
                    session.query(SQLAlchemyUser)
                    .order_by(SQLAlchemyUser.created_at.desc())
                    .offset(pagination.offset)
                    .limit(pagination.limit)
                    .all()
                )
                
                users = []
                for db_user in db_users:
                    user_response = UserResponse(
                        id=db_user.id,
                        username=db_user.username,
                        email=db_user.email,
                        role=db_user.role,
                        created_at=db_user.created_at,
                        is_admin=db_user.role == "admin"
                    )
                    users.append(user_response)
                
            finally:
                session.close()
        else:
            # For in-memory backend, return current user only
            users = [UserResponse(
                id=current_user.id,
                username=current_user.username,
                email=getattr(current_user, 'email', None),
                role=current_user.role,
                created_at=current_user.created_at,
                is_admin=current_user.is_admin()
            )]
            total = 1
        
        return PaginatedResponse.create(
            items=users,
            page=pagination.page,
            limit=pagination.limit,
            total=total
        )
        
    except Exception as e:
        logger.error(f"Error listing users: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve users"
        )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    current_user: User = Depends(get_current_admin_user)
) -> UserResponse:
    """
    Get a specific user by ID (admin only).
    
    Args:
        user_id: User ID to retrieve
        current_user: Current authenticated admin user
        
    Returns:
        UserResponse: User information
    """
    try:
        backend = get_database_manager().get_backend()
        
        if hasattr(backend, '_get_session'):
            session = backend._get_session()
            try:
                from mini_llm_chat.backends.postgresql import SQLAlchemyUser
                
                db_user = (
                    session.query(SQLAlchemyUser)
                    .filter(SQLAlchemyUser.id == user_id)
                    .first()
                )
                
                if not db_user:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="User not found"
                    )
                
                return UserResponse(
                    id=db_user.id,
                    username=db_user.username,
                    email=db_user.email,
                    role=db_user.role,
                    created_at=db_user.created_at,
                    is_admin=db_user.role == "admin"
                )
                
            finally:
                session.close()
        else:
            # For in-memory backend, only return current user if ID matches
            if user_id == current_user.id:
                return UserResponse(
                    id=current_user.id,
                    username=current_user.username,
                    email=getattr(current_user, 'email', None),
                    role=current_user.role,
                    created_at=current_user.created_at,
                    is_admin=current_user.is_admin()
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user"
        )


@router.get("/{user_id}/stats", response_model=ConversationStatsResponse)
async def get_user_stats_by_id(
    user_id: int,
    current_user: User = Depends(get_current_admin_user)
) -> ConversationStatsResponse:
    """
    Get statistics for a specific user (admin only).
    
    Args:
        user_id: User ID to get stats for
        current_user: Current authenticated admin user
        
    Returns:
        ConversationStatsResponse: User statistics
    """
    try:
        backend = get_database_manager().get_backend()
        
        if hasattr(backend, '_get_session'):
            session = backend._get_session()
            try:
                from mini_llm_chat.backends.postgresql import SQLAlchemyConversation, SQLAlchemyMessage, SQLAlchemyUser
                
                # Verify user exists
                user_exists = (
                    session.query(SQLAlchemyUser)
                    .filter(SQLAlchemyUser.id == user_id)
                    .first()
                )
                
                if not user_exists:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="User not found"
                    )
                
                # Count conversations
                total_conversations = (
                    session.query(SQLAlchemyConversation)
                    .filter(SQLAlchemyConversation.user_id == user_id)
                    .count()
                )
                
                # Count messages
                total_messages = (
                    session.query(SQLAlchemyMessage)
                    .join(SQLAlchemyConversation)
                    .filter(SQLAlchemyConversation.user_id == user_id)
                    .count()
                )
                
                # Sum tokens
                total_tokens_result = (
                    session.query(session.query(SQLAlchemyMessage.token_count).label('sum'))
                    .join(SQLAlchemyConversation)
                    .filter(SQLAlchemyConversation.user_id == user_id)
                    .filter(SQLAlchemyMessage.token_count.isnot(None))
                    .scalar()
                )
                total_tokens = total_tokens_result if total_tokens_result else 0
                
                # Get most recent conversation
                most_recent = (
                    session.query(SQLAlchemyConversation.updated_at)
                    .filter(SQLAlchemyConversation.user_id == user_id)
                    .order_by(SQLAlchemyConversation.updated_at.desc())
                    .first()
                )
                most_recent_conversation = most_recent[0] if most_recent else None
                
            finally:
                session.close()
        else:
            # For in-memory backend, only return stats if user_id matches current user
            if user_id == current_user.id:
                total_conversations = 0
                total_messages = 0
                total_tokens = 0
                most_recent_conversation = None
            else:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
        
        return ConversationStatsResponse(
            total_conversations=total_conversations,
            total_messages=total_messages,
            total_tokens=total_tokens,
            most_recent_conversation=most_recent_conversation
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting stats for user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user statistics"
        )
