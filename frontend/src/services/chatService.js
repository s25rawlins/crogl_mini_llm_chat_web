import api from './api';

export const chatService = {
  async getConversations(page = 1, limit = 20) {
    try {
      const response = await api.get('/chat/conversations', {
        params: { page, limit },
      });
      return response.data;
    } catch (error) {
      throw new Error(
        error.response?.data?.message || 'Failed to fetch conversations'
      );
    }
  },

  async getConversation(conversationId) {
    try {
      const response = await api.get(`/chat/conversations/${conversationId}`);
      return response.data;
    } catch (error) {
      throw new Error(
        error.response?.data?.message || 'Failed to fetch conversation'
      );
    }
  },

  async createConversation(title = null, initialMessage = null) {
    try {
      const response = await api.post('/chat/conversations', {
        title,
        initial_message: initialMessage,
      });
      return response.data;
    } catch (error) {
      throw new Error(
        error.response?.data?.message || 'Failed to create conversation'
      );
    }
  },

  async sendMessage(conversationId, content) {
    try {
      const response = await api.post(`/chat/conversations/${conversationId}/messages`, {
        content,
        conversation_id: conversationId,
      });
      return response.data;
    } catch (error) {
      throw new Error(
        error.response?.data?.message || 'Failed to send message'
      );
    }
  },

  async updateConversation(conversationId, title) {
    try {
      const response = await api.put(`/chat/conversations/${conversationId}`, {
        title,
      });
      return response.data;
    } catch (error) {
      throw new Error(
        error.response?.data?.message || 'Failed to update conversation'
      );
    }
  },

  async deleteConversation(conversationId) {
    try {
      const response = await api.delete(`/chat/conversations/${conversationId}`);
      return response.data;
    } catch (error) {
      throw new Error(
        error.response?.data?.message || 'Failed to delete conversation'
      );
    }
  },

  async clearConversation(conversationId, keepSystemMessage = true) {
    try {
      const response = await api.post(`/chat/conversations/${conversationId}/clear`, {
        keep_system_message: keepSystemMessage,
      });
      return response.data;
    } catch (error) {
      throw new Error(
        error.response?.data?.message || 'Failed to clear conversation'
      );
    }
  },

  async getChatStatus(conversationId = null) {
    try {
      const params = conversationId ? { conversation_id: conversationId } : {};
      const response = await api.get('/chat/status', { params });
      return response.data;
    } catch (error) {
      throw new Error(
        error.response?.data?.message || 'Failed to get chat status'
      );
    }
  },

  // WebSocket connection for real-time chat
  createWebSocketConnection(token, onMessage, onError, onClose) {
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsHost = window.location.host;
    const wsUrl = `${wsProtocol}//${wsHost}/ws/chat?token=${encodeURIComponent(token)}`;
    
    const ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
      console.log('WebSocket connected');
    };
    
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        onMessage(data);
      } catch (error) {
        console.error('Failed to parse WebSocket message:', error);
      }
    };
    
    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      onError(error);
    };
    
    ws.onclose = (event) => {
      console.log('WebSocket closed:', event.code, event.reason);
      onClose(event);
    };
    
    return ws;
  },

  sendWebSocketMessage(ws, type, data) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type, ...data }));
    } else {
      throw new Error('WebSocket is not connected');
    }
  },
};
