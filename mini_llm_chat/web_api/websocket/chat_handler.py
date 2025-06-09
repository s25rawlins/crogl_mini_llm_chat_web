"""
WebSocket Chat Handler

This module provides WebSocket functionality for real-time chat streaming,
allowing clients to receive AI responses as they are generated.
"""

import json
import logging
import os
from typing import Dict, List, cast, Iterator

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, status
from openai import OpenAI
from openai.types.chat import ChatCompletionChunk

from mini_llm_chat.auth import get_user_by_token
from mini_llm_chat.cache import get_cache, hash_request
from mini_llm_chat.chat import estimate_tokens, SYSTEM_INSTRUCTION, DEFAULT_MODEL, TEMPERATURE, MAX_TOKENS
from mini_llm_chat.database_manager import (
    add_message,
    create_conversation,
    get_conversation_messages,
    get_database_manager,
)
from mini_llm_chat.web_api.dependencies import get_rate_limiter, validate_conversation_access

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages WebSocket connections for real-time chat."""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
    
    async def connect(self, websocket: WebSocket, user_id: int) -> str:
        """Accept a WebSocket connection and assign a connection ID."""
        await websocket.accept()
        connection_id = f"user_{user_id}_{id(websocket)}"
        self.active_connections[connection_id] = websocket
        logger.info(f"WebSocket connection established: {connection_id}")
        return connection_id
    
    def disconnect(self, connection_id: str):
        """Remove a WebSocket connection."""
        if connection_id in self.active_connections:
            del self.active_connections[connection_id]
            logger.info(f"WebSocket connection closed: {connection_id}")
    
    async def send_message(self, connection_id: str, message: dict):
        """Send a message to a specific connection."""
        if connection_id in self.active_connections:
            websocket = self.active_connections[connection_id]
            try:
                await websocket.send_text(json.dumps(message))
            except Exception as e:
                logger.error(f"Error sending message to {connection_id}: {e}")
                self.disconnect(connection_id)
    
    async def send_error(self, connection_id: str, error_message: str):
        """Send an error message to a connection."""
        await self.send_message(connection_id, {
            "type": "error",
            "error": error_message
        })
    
    async def send_stream_chunk(self, connection_id: str, content: str):
        """Send a streaming content chunk."""
        await self.send_message(connection_id, {
            "type": "stream",
            "content": content
        })
    
    async def send_stream_complete(self, connection_id: str, message_id: int, conversation_id: int):
        """Send stream completion notification."""
        await self.send_message(connection_id, {
            "type": "complete",
            "message_id": message_id,
            "conversation_id": conversation_id
        })


# Global connection manager
manager = ConnectionManager()


async def authenticate_websocket(websocket: WebSocket, token: str):
    """
    Authenticate a WebSocket connection using JWT token.
    
    Args:
        websocket: WebSocket connection
        token: JWT token
        
    Returns:
        User: Authenticated user or None if authentication fails
    """
    try:
        user = get_user_by_token(token)
        if not user:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid token")
            return None
        return user
    except Exception as e:
        logger.error(f"WebSocket authentication error: {e}")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Authentication failed")
        return None


async def handle_chat_message(
    connection_id: str,
    user,
    message_data: dict
):
    """
    Handle a chat message received via WebSocket.
    
    Args:
        connection_id: WebSocket connection ID
        user: Authenticated user
        message_data: Message data from client
    """
    try:
        # Validate message data
        if "content" not in message_data:
            await manager.send_error(connection_id, "Message content is required")
            return
        
        content = message_data["content"].strip()
        if not content:
            await manager.send_error(connection_id, "Message content cannot be empty")
            return
        
        if len(content) > 1000:
            await manager.send_error(connection_id, "Message content too long")
            return
        
        # Get or create conversation
        conversation_id = message_data.get("conversation_id")
        if conversation_id:
            # Validate conversation access
            if not validate_conversation_access(user, conversation_id):
                await manager.send_error(connection_id, "Access to conversation denied")
                return
        else:
            # Create new conversation
            conversation = create_conversation(user.id)
            if not conversation:
                await manager.send_error(connection_id, "Failed to create conversation")
                return
            conversation_id = conversation.id
            
            # Add system message
            add_message(conversation_id, "system", SYSTEM_INSTRUCTION)
        
        # Apply rate limiting
        try:
            rate_limiter = get_rate_limiter()
            rate_limiter.acquire()
        except Exception as e:
            await manager.send_error(connection_id, "Rate limit exceeded")
            return
        
        # Add user message to conversation
        user_message = add_message(
            conversation_id,
            "user",
            content,
            estimate_tokens(content)
        )
        
        if not user_message:
            await manager.send_error(connection_id, "Failed to save user message")
            return
        
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
            # Send cached response
            await manager.send_stream_chunk(connection_id, cached_response)
            
            # Add to database
            ai_message = add_message(
                conversation_id,
                "assistant",
                cached_response,
                estimate_tokens(cached_response)
            )
            
            await manager.send_stream_complete(connection_id, ai_message.id, conversation_id)
            logger.info(f"Served cached response via WebSocket for conversation {conversation_id}")
            return
        
        # Get OpenAI API key
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            await manager.send_error(connection_id, "OpenAI API key not configured")
            return
        
        # Make streaming API call to OpenAI
        client = OpenAI(api_key=api_key)
        
        try:
            response_stream: Iterator[ChatCompletionChunk] = cast(
                Iterator[ChatCompletionChunk],
                client.chat.completions.create(
                    model=DEFAULT_MODEL,
                    messages=conversation_history,
                    stream=True,
                    temperature=TEMPERATURE,
                    max_tokens=MAX_TOKENS,
                ),
            )
            
            collected_chunks: List[str] = []
            
            for chunk in response_stream:
                if chunk.choices and len(chunk.choices) > 0:
                    delta = chunk.choices[0].delta
                    if hasattr(delta, "content") and delta.content:
                        content_chunk = delta.content
                        # Security: Remove ANSI escape sequences
                        safe_content = content_chunk.replace("\x1b", "")
                        collected_chunks.append(safe_content)
                        
                        # Send chunk to client
                        await manager.send_stream_chunk(connection_id, safe_content)
            
            # Combine all chunks
            assistant_message = "".join(collected_chunks)
            
            if assistant_message.strip():
                # Add to database
                ai_message = add_message(
                    conversation_id,
                    "assistant",
                    assistant_message,
                    estimate_tokens(assistant_message)
                )
                
                # Cache the response
                cache.cache_api_response(request_hash, assistant_message)
                
                # Send completion notification
                await manager.send_stream_complete(connection_id, ai_message.id, conversation_id)
                
                logger.info(f"AI response streamed via WebSocket for conversation {conversation_id}")
            else:
                await manager.send_error(connection_id, "Received empty response from AI")
                
        except Exception as e:
            logger.error(f"Error during OpenAI API call: {e}")
            await manager.send_error(connection_id, f"AI service error: {str(e)}")
    
    except Exception as e:
        logger.error(f"Error handling chat message: {e}")
        await manager.send_error(connection_id, "Failed to process message")


async def websocket_chat_endpoint(websocket: WebSocket, token: str):
    """
    WebSocket endpoint for real-time chat.
    
    Args:
        websocket: WebSocket connection
        token: JWT authentication token
    """
    # Authenticate user
    user = await authenticate_websocket(websocket, token)
    if not user:
        return
    
    # Establish connection
    connection_id = await manager.connect(websocket, user.id)
    
    try:
        # Send welcome message
        await manager.send_message(connection_id, {
            "type": "connected",
            "message": f"Connected as {user.username}",
            "user_id": user.id
        })
        
        # Listen for messages
        while True:
            try:
                # Receive message from client
                data = await websocket.receive_text()
                message_data = json.loads(data)
                
                # Handle different message types
                message_type = message_data.get("type", "chat")
                
                if message_type == "chat":
                    await handle_chat_message(connection_id, user, message_data)
                elif message_type == "ping":
                    # Respond to ping with pong
                    await manager.send_message(connection_id, {"type": "pong"})
                else:
                    await manager.send_error(connection_id, f"Unknown message type: {message_type}")
                    
            except json.JSONDecodeError:
                await manager.send_error(connection_id, "Invalid JSON format")
            except Exception as e:
                logger.error(f"Error processing WebSocket message: {e}")
                await manager.send_error(connection_id, "Failed to process message")
                
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected: {connection_id}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        manager.disconnect(connection_id)


def setup_websocket_routes(app: FastAPI):
    """
    Set up WebSocket routes for the FastAPI application.
    
    Args:
        app: FastAPI application instance
    """
    @app.websocket("/ws/chat")
    async def websocket_chat(websocket: WebSocket, token: str):
        """WebSocket endpoint for real-time chat."""
        await websocket_chat_endpoint(websocket, token)
    
    logger.info("WebSocket routes configured")
