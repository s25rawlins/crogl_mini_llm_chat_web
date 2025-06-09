import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../../hooks/useAuth';
import { chatService } from '../../services/chatService';
import { authService } from '../../services/authService';
import Header from '../Layout/Header';
import Sidebar from '../Layout/Sidebar';
import MessageList from './MessageList';
import MessageInput from './MessageInput';
import Loading from '../Common/Loading';

const ChatContainer = () => {
  const { user } = useAuth();
  const [conversations, setConversations] = useState([]);
  const [currentConversation, setCurrentConversation] = useState(null);
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState(null);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [websocket, setWebsocket] = useState(null);

  const handleWebSocketMessage = useCallback((data) => {
    switch (data.type) {
      case 'connected':
        console.log('WebSocket connected:', data.message);
        break;
      case 'stream':
        // Handle streaming content
        setMessages(prev => {
          const lastMessage = prev[prev.length - 1];
          if (lastMessage && lastMessage.role === 'assistant' && lastMessage.streaming) {
            // Append to existing streaming message
            return prev.map((msg, index) => 
              index === prev.length - 1 
                ? { ...msg, content: msg.content + data.content }
                : msg
            );
          } else {
            // Start new streaming message
            return [...prev, {
              id: `temp-${Date.now()}`,
              role: 'assistant',
              content: data.content,
              streaming: true,
              created_at: new Date().toISOString(),
            }];
          }
        });
        break;
      case 'complete':
        // Mark streaming as complete
        setMessages(prev => 
          prev.map(msg => 
            msg.streaming 
              ? { ...msg, id: data.message_id, streaming: false }
              : msg
          )
        );
        setSending(false);
        break;
      case 'error':
        console.error('WebSocket error:', data.error);
        setError(data.error);
        setSending(false);
        break;
      default:
        console.log('Unknown WebSocket message type:', data.type);
    }
  }, []);

  const handleWebSocketError = useCallback((error) => {
    console.error('WebSocket error:', error);
    setError('Connection error. Please try again.');
    setSending(false);
  }, []);

  const handleWebSocketClose = useCallback((event) => {
    console.log('WebSocket closed:', event.code, event.reason);
    if (event.code !== 1000) { // Not a normal closure
      setError('Connection lost. Please refresh the page.');
    }
  }, []);

  const setupWebSocket = useCallback(() => {
    if (websocket) {
      websocket.close();
    }

    const token = authService.getStoredToken();
    if (!token) return;

    const ws = chatService.createWebSocketConnection(
      token,
      handleWebSocketMessage,
      handleWebSocketError,
      handleWebSocketClose
    );

    setWebsocket(ws);
  }, [websocket, handleWebSocketMessage, handleWebSocketError, handleWebSocketClose]);

  const loadConversation = useCallback(async (conversationId) => {
    try {
      const data = await chatService.getConversation(conversationId);
      setCurrentConversation(data.conversation);
      setMessages(data.messages || []);
      setError(null);
    } catch (error) {
      console.error('Failed to load conversation:', error);
      setError('Failed to load conversation.');
    }
  }, []);

  const createNewConversation = useCallback(async (initialMessage = null) => {
    try {
      const conversation = await chatService.createConversation(
        'New Chat',
        initialMessage
      );
      
      setCurrentConversation(conversation);
      setConversations(prev => [conversation, ...prev]);
      
      // Load the conversation with messages
      await loadConversation(conversation.id);
      
      return conversation;
    } catch (error) {
      console.error('Failed to create conversation:', error);
      setError('Failed to create new conversation.');
      return null;
    }
  }, [loadConversation]);

  const initializeChat = useCallback(async () => {
    try {
      setLoading(true);
      
      // Load conversations
      const conversationsData = await chatService.getConversations();
      setConversations(conversationsData.items || []);
      
      // Load the most recent conversation or create a new one
      if (conversationsData.items && conversationsData.items.length > 0) {
        const latest = conversationsData.items[0];
        await loadConversation(latest.id);
      } else {
        await createNewConversation();
      }
    } catch (error) {
      console.error('Failed to initialize chat:', error);
      setError('Failed to load chat. Please try again.');
    } finally {
      setLoading(false);
    }
  }, [loadConversation, createNewConversation]);

  useEffect(() => {
    initializeChat();
    return () => {
      if (websocket) {
        websocket.close();
      }
    };
  }, [initializeChat, websocket]);

  useEffect(() => {
    if (currentConversation && user) {
      setupWebSocket();
    }
    return () => {
      if (websocket) {
        websocket.close();
      }
    };
  }, [currentConversation, user, setupWebSocket, websocket]);

  const sendMessage = async (content) => {
    if (!content.trim() || sending) return;

    try {
      setSending(true);
      setError(null);

      // If no current conversation, create one
      let conversation = currentConversation;
      if (!conversation) {
        conversation = await createNewConversation();
        if (!conversation) return;
      }

      // Add user message to UI immediately
      const userMessage = {
        id: `temp-user-${Date.now()}`,
        role: 'user',
        content: content.trim(),
        created_at: new Date().toISOString(),
      };
      setMessages(prev => [...prev, userMessage]);

      // Send via WebSocket for real-time streaming
      if (websocket && websocket.readyState === WebSocket.OPEN) {
        chatService.sendWebSocketMessage(websocket, 'chat', {
          content: content.trim(),
          conversation_id: conversation.id,
        });
      } else {
        // Fallback to HTTP API
        const response = await chatService.sendMessage(conversation.id, content.trim());
        setMessages(prev => [...prev, response]);
        setSending(false);
      }
    } catch (error) {
      console.error('Failed to send message:', error);
      setError('Failed to send message. Please try again.');
      setSending(false);
    }
  };

  const deleteConversation = async (conversationId) => {
    try {
      await chatService.deleteConversation(conversationId);
      setConversations(prev => prev.filter(c => c.id !== conversationId));
      
      if (currentConversation?.id === conversationId) {
        // Load another conversation or create new one
        const remaining = conversations.filter(c => c.id !== conversationId);
        if (remaining.length > 0) {
          await loadConversation(remaining[0].id);
        } else {
          await createNewConversation();
        }
      }
    } catch (error) {
      console.error('Failed to delete conversation:', error);
      setError('Failed to delete conversation.');
    }
  };

  if (loading) {
    return <Loading message="Loading chat..." />;
  }

  return (
    <div className="chat-container">
      <Header 
        user={user}
        onToggleSidebar={() => setSidebarOpen(!sidebarOpen)}
        sidebarOpen={sidebarOpen}
      />
      
      <div className="chat-main">
        <Sidebar
          conversations={conversations}
          currentConversation={currentConversation}
          onSelectConversation={loadConversation}
          onNewConversation={() => createNewConversation()}
          onDeleteConversation={deleteConversation}
          isOpen={sidebarOpen}
        />
        
        <div className="chat-content">
          {error && (
            <div className="error-banner">
              {error}
              <button onClick={() => setError(null)} className="error-close">×</button>
            </div>
          )}
          
          <MessageList 
            messages={messages}
            loading={sending}
          />
          
          <MessageInput
            onSendMessage={sendMessage}
            disabled={sending}
            placeholder={sending ? "AI is responding..." : "Type your message..."}
          />
        </div>
      </div>
    </div>
  );
};

export default ChatContainer;
