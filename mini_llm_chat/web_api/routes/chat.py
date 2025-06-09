"""
Chat Routes

This module contains FastAPI routes for chat functionality,
including conversations, messages, and real-time chat interactions.
"""

import logging
import time
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse

from mini_llm_chat.backends.base import User
from mini_llm_chat.cache import get_cache, hash_request
from mini_llm_chat.chat import estimate_tokens, SYSTEM_INSTRUCTION, DEFAULT_MODEL, TEMPERATURE, MAX_TOKENS
from mini_llm_chat.database_manager import (
    add_message,
    create_conversation,
    get_conversation_messages,
    get_database_manager,
    truncate_conversation_messages,
)
from mini_llm_chat.web_api.dependencies import (
    apply_rate_limit,
    get_current_user,
    get_openai_api_key,
    verify_conversation_access,
)
from mini_llm_chat.web_api.models.chat import (
    ChatStatusResponse,
    ClearConversationRequest,
    ClearConversationResponse,
    ConversationListResponse,
    ConversationResponse,
    ConversationStatsResponse,
    ConversationWithMessagesResponse,
    CreateConversationRequest,
    DeleteConversationResponse,
    MessageRequest,
    MessageResponse,
    SearchMessagesRequest,
    SearchMessagesResponse,
    UpdateConversationRequest,
)
from mini_llm_chat.web_api.models.common import PaginationParams, PaginatedResponse

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/conversations", response_model=PaginatedResponse[ConversationResponse])
async def list_conversations(
    pagination: PaginationParams = Depends(),
    current_user: User = Depends(get_current_user)
) -> PaginatedResponse[ConversationResponse]:
    """
    List user's conversations with pagination.
    
    Args:
        pagination: Pagination parameters
        current_user: Current authenticated user
        
    Returns:
        PaginatedResponse[ConversationResponse]: Paginated list of conversations
    """
    try:
        backend = get_database_manager().get_backend()
        
        # For PostgreSQL backend, query conversations with pagination
        if hasattr(backend, '_get_session'):
            session = backend._get_session()
            try:
                from mini_llm_chat.backends.postgresql import SQLAlchemyConversation
                
                # Get total count
                total = (
                    session.query(SQLAlchemyConversation)
                    .filter(SQLAlchemyConversation.user_id == current_user.id)
                    .count()
                )
                
                # Get conversations for current page
                db_conversations = (
                    session.query(SQLAlchemyConversation)
                    .filter(SQLAlchemyConversation.user_id == current_user.id)
                    .order_by(SQLAlchemyConversation.updated_at.desc())
                    .offset(pagination.offset)
                    .limit(pagination.limit)
                    .all()
                )
                
                conversations = []
                for db_conv in db_conversations:
                    # Count messages for each conversation
                    message_count = (
                        session.query(backend.SQLAlchemyMessage)
                        .filter(backend.SQLAlchemyMessage.conversation_id == db_conv.id)
                        .count()
                    )
                    
                    conv_response = ConversationResponse(
                        id=db_conv.id,
                        user_id=db_conv.user_id,
                        title=db_conv.title,
                        created_at=db_conv.created_at,
                        updated_at=db_conv.updated_at,
                        message_count=message_count
                    )
                    conversations.append(conv_response)
                
            finally:
                session.close()
        else:
            # For in-memory backend, return empty list or session conversations
            conversations = []
            total = 0
        
        return PaginatedResponse.create(
            items=conversations,
            page=pagination.page,
            limit=pagination.limit,
            total=total
        )
        
    except Exception as e:
        logger.error(f"Error listing conversations for user {current_user.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve conversations"
        )


@router.post("/conversations", response_model=ConversationResponse)
async def create_new_conversation(
    conversation_data: CreateConversationRequest,
    current_user: User = Depends(get_current_user)
) -> ConversationResponse:
    """
    Create a new conversation.
    
    Args:
        conversation_data: Conversation creation data
        current_user: Current authenticated user
        
    Returns:
        ConversationResponse: Created conversation
    """
    try:
        # Create conversation
        conversation = create_conversation(
            current_user.id,
            conversation_data.title
        )
        
        if not conversation:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create conversation"
            )
        
        # Add system message
        add_message(conversation.id, "system", SYSTEM_INSTRUCTION)
        
        # Add initial message if provided
        if conversation_data.initial_message:
            add_message(
                conversation.id,
                "user",
                conversation_data.initial_message,
                estimate_tokens(conversation_data.initial_message)
            )
        
        logger.info(f"Created conversation {conversation.id} for user {current_user.username}")
        
        return ConversationResponse(
            id=conversation.id,
            user_id=conversation.user_id,
            title=conversation.title,
            created_at=conversation.created_at,
            updated_at=conversation.updated_at,
            message_count=2 if conversation_data.initial_message else 1
        )
        
    except Exception as e:
        logger.error(f"Error creating conversation for user {current_user.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create conversation"
        )


@router.get("/conversations/{conversation_id}", response_model=ConversationWithMessagesResponse)
async def get_conversation(
    conversation_id: int = Depends(verify_conversation_access),
    current_user: User = Depends(get_current_user)
) -> ConversationWithMessagesResponse:
    """
    Get a conversation with its messages.
    
    Args:
        conversation_id: Conversation ID (verified by dependency)
        current_user: Current authenticated user
        
    Returns:
        ConversationWithMessagesResponse: Conversation with messages
    """
    try:
        backend = get_database_manager().get_backend()
        
        # Get conversation details
        if hasattr(backend, '_get_session'):
            session = backend._get_session()
            try:
                from mini_llm_chat.backends.postgresql import SQLAlchemyConversation
                
                db_conversation = (
                    session.query(SQLAlchemyConversation)
                    .filter(SQLAlchemyConversation.id == conversation_id)
                    .first()
                )
                
                if not db_conversation:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Conversation not found"
                    )
                
                conversation = ConversationResponse(
                    id=db_conversation.id,
                    user_id=db_conversation.user_id,
                    title=db_conversation.title,
                    created_at=db_conversation.created_at,
                    updated_at=db_conversation.updated_at
                )
                
            finally:
                session.close()
        else:
            # For in-memory backend, create a mock conversation
            conversation = ConversationResponse(
                id=conversation_id,
                user_id=current_user.id,
                title="Chat Session",
                created_at=current_user.created_at,
                updated_at=current_user.created_at
            )
        
        # Get messages
        db_messages = get_conversation_messages(conversation_id)
        messages = []
        
        for msg in db_messages:
            message_response = MessageResponse(
                id=msg.id,
                conversation_id=msg.conversation_id,
                role=msg.role,
                content=msg.content,
                token_count=msg.token_count,
                created_at=msg.created_at
            )
            messages.append(message_response)
        
        return ConversationWithMessagesResponse(
            conversation=conversation,
            messages=messages
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting conversation {conversation_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve conversation"
        )


@router.post("/conversations/{conversation_id}/messages", response_model=MessageResponse)
async def send_message(
    message_data: MessageRequest,
    conversation_id: int = Depends(verify_conversation_access),
    current_user: User = Depends(get_current_user),
    api_key: str = Depends(get_openai_api_key),
    _: None = Depends(apply_rate_limit)
) -> MessageResponse:
    """
    Send a message to a conversation and get AI response.
    
    Args:
        message_data: Message content
        conversation_id: Conversation ID (verified by dependency)
        current_user: Current authenticated user
        api_key: OpenAI API key
        _: Rate limit check
        
    Returns:
        MessageResponse: AI response message
    """
    try:
        from openai import OpenAI
        
        # Add user message to conversation
        user_message = add_message(
            conversation_id,
            "user",
            message_data.content,
            estimate_tokens(message_data.content)
        )
        
        if not user_message:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to save user message"
            )
        
        # Get conversation history
        db_messages = get_conversation_messages(conversation_id)
        conversation_history = []
        
        for msg in db_messages:
            conversation_history.append({
                "role": msg.role,
                "content": msg.content
            })
        
        # Check cache
        cache = get_cache()
        request_hash = hash_request(conversation_history, DEFAULT_MODEL, TEMPERATURE)
        cached_response = cache.get_cached_api_response(request_hash)
        
        if cached_response:
            # Add cached response to database
            ai_message = add_message(
                conversation_id,
                "assistant",
                cached_response,
                estimate_tokens(cached_response)
            )
            
            logger.info(f"Served cached response for conversation {conversation_id}")
            
            return MessageResponse(
                id=ai_message.id,
                conversation_id=ai_message.conversation_id,
                role=ai_message.role,
                content=ai_message.content,
                token_count=ai_message.token_count,
                created_at=ai_message.created_at
            )
        
        # Make API call to OpenAI
        client = OpenAI(api_key=api_key)
        
        response = client.chat.completions.create(
            model=DEFAULT_MODEL,
            messages=conversation_history,
            temperature=TEMPERATURE,
            max_tokens=MAX_TOKENS,
        )
        
        ai_content = response.choices[0].message.content
        
        if not ai_content:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Received empty response from AI"
            )
        
        # Add AI response to database
        ai_message = add_message(
            conversation_id,
            "assistant",
            ai_content,
            estimate_tokens(ai_content)
        )
        
        # Cache the response
        cache.cache_api_response(request_hash, ai_content)
        
        logger.info(f"AI response added to conversation {conversation_id}")
        
        return MessageResponse(
            id=ai_message.id,
            conversation_id=ai_message.conversation_id,
            role=ai_message.role,
            content=ai_message.content,
            token_count=ai_message.token_count,
            created_at=ai_message.created_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error sending message to conversation {conversation_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process message"
        )


@router.put("/conversations/{conversation_id}", response_model=ConversationResponse)
async def update_conversation(
    update_data: UpdateConversationRequest,
    conversation_id: int = Depends(verify_conversation_access),
    current_user: User = Depends(get_current_user)
) -> ConversationResponse:
    """
    Update conversation title.
    
    Args:
        update_data: Update data
        conversation_id: Conversation ID (verified by dependency)
        current_user: Current authenticated user
        
    Returns:
        ConversationResponse: Updated conversation
    """
    try:
        backend = get_database_manager().get_backend()
        
        if hasattr(backend, '_get_session'):
            session = backend._get_session()
            try:
                from mini_llm_chat.backends.postgresql import SQLAlchemyConversation
                
                db_conversation = (
                    session.query(SQLAlchemyConversation)
                    .filter(SQLAlchemyConversation.id == conversation_id)
                    .first()
                )
                
                if not db_conversation:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Conversation not found"
                    )
                
                db_conversation.title = update_data.title
                session.commit()
                
                return ConversationResponse(
                    id=db_conversation.id,
                    user_id=db_conversation.user_id,
                    title=db_conversation.title,
                    created_at=db_conversation.created_at,
                    updated_at=db_conversation.updated_at
                )
                
            finally:
                session.close()
        else:
            # For in-memory backend, return mock response
            return ConversationResponse(
                id=conversation_id,
                user_id=current_user.id,
                title=update_data.title,
                created_at=current_user.created_at,
                updated_at=current_user.created_at
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating conversation {conversation_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update conversation"
        )


@router.delete("/conversations/{conversation_id}", response_model=DeleteConversationResponse)
async def delete_conversation(
    conversation_id: int = Depends(verify_conversation_access),
    current_user: User = Depends(get_current_user)
) -> DeleteConversationResponse:
    """
    Delete a conversation and all its messages.
    
    Args:
        conversation_id: Conversation ID (verified by dependency)
        current_user: Current authenticated user
        
    Returns:
        DeleteConversationResponse: Deletion confirmation
    """
    try:
        backend = get_database_manager().get_backend()
        
        if hasattr(backend, '_get_session'):
            session = backend._get_session()
            try:
                from mini_llm_chat.backends.postgresql import SQLAlchemyConversation, SQLAlchemyMessage
                
                # Count messages before deletion
                message_count = (
                    session.query(SQLAlchemyMessage)
                    .filter(SQLAlchemyMessage.conversation_id == conversation_id)
                    .count()
                )
                
                # Delete messages first
                session.query(SQLAlchemyMessage).filter(
                    SQLAlchemyMessage.conversation_id == conversation_id
                ).delete()
                
                # Delete conversation
                deleted_count = session.query(SQLAlchemyConversation).filter(
                    SQLAlchemyConversation.id == conversation_id
                ).delete()
                
                session.commit()
                
                if deleted_count == 0:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Conversation not found"
                    )
                
                logger.info(f"Deleted conversation {conversation_id} with {message_count} messages")
                
                return DeleteConversationResponse(
                    deleted_conversation_id=conversation_id,
                    deleted_messages_count=message_count
                )
                
            finally:
                session.close()
        else:
            # For in-memory backend, return mock response
            return DeleteConversationResponse(
                deleted_conversation_id=conversation_id,
                deleted_messages_count=0
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting conversation {conversation_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete conversation"
        )


@router.post("/conversations/{conversation_id}/clear", response_model=ClearConversationResponse)
async def clear_conversation(
    clear_data: ClearConversationRequest,
    conversation_id: int = Depends(verify_conversation_access),
    current_user: User = Depends(get_current_user)
) -> ClearConversationResponse:
    """
    Clear messages from a conversation.
    
    Args:
        clear_data: Clear options
        conversation_id: Conversation ID (verified by dependency)
        current_user: Current authenticated user
        
    Returns:
        ClearConversationResponse: Clear operation result
    """
    try:
        # Get current message count
        db_messages = get_conversation_messages(conversation_id)
        initial_count = len(db_messages)
        
        if clear_data.keep_system_message:
            # Keep only the system message (first message)
            truncate_conversation_messages(conversation_id, 1)
            remaining_count = 1
            cleared_count = initial_count - 1
        else:
            # Clear all messages
            truncate_conversation_messages(conversation_id, 0)
            remaining_count = 0
            cleared_count = initial_count
        
        logger.info(f"Cleared {cleared_count} messages from conversation {conversation_id}")
        
        return ClearConversationResponse(
            conversation_id=conversation_id,
            cleared_messages_count=cleared_count,
            remaining_messages_count=remaining_count
        )
        
    except Exception as e:
        logger.error(f"Error clearing conversation {conversation_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to clear conversation"
        )


@router.get("/status", response_model=ChatStatusResponse)
async def get_chat_status(
    conversation_id: Optional[int] = None,
    current_user: User = Depends(get_current_user)
) -> ChatStatusResponse:
    """
    Get chat status information.
    
    Args:
        conversation_id: Optional conversation ID to get specific status
        current_user: Current authenticated user
        
    Returns:
        ChatStatusResponse: Chat status information
    """
    try:
        from mini_llm_chat.web_api.dependencies import get_rate_limiter
        
        # Get rate limiter info
        rate_limiter = get_rate_limiter()
        remaining_calls = rate_limiter.get_remaining_calls()
        
        # If no conversation_id provided, get the most recent one
        if conversation_id is None:
            backend = get_database_manager().get_backend()
            if hasattr(backend, '_get_session'):
                session = backend._get_session()
                try:
                    from mini_llm_chat.backends.postgresql import SQLAlchemyConversation
                    
                    latest_conv = (
                        session.query(SQLAlchemyConversation)
                        .filter(SQLAlchemyConversation.user_id == current_user.id)
                        .order_by(SQLAlchemyConversation.updated_at.desc())
                        .first()
                    )
                    
                    if latest_conv:
                        conversation_id = latest_conv.id
                    else:
                        conversation_id = 0
                        
                finally:
                    session.close()
            else:
                conversation_id = 1  # Default for in-memory
        
        # Get message count for the conversation
        if conversation_id > 0:
            db_messages = get_conversation_messages(conversation_id)
            message_count = len(db_messages)
        else:
            message_count = 0
        
        return ChatStatusResponse(
            conversation_id=conversation_id,
            message_count=message_count,
            rate_limit_remaining=remaining_calls,
            model=DEFAULT_MODEL
        )
        
    except Exception as e:
        logger.error(f"Error getting chat status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get chat status"
        )
