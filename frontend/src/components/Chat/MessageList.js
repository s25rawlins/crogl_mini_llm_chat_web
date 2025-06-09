import React, { useEffect, useRef } from 'react';
import Message from './Message';

const MessageList = ({ messages, loading }) => {
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Filter out system messages for display
  const displayMessages = messages.filter(msg => msg.role !== 'system');

  return (
    <div className="message-list">
      <div className="message-list-content">
        {displayMessages.length === 0 ? (
          <div className="message-list-empty">
            <div className="empty-state">
              <h3>Welcome to Mini LLM Chat</h3>
              <p>Start a conversation by typing a message below.</p>
            </div>
          </div>
        ) : (
          displayMessages.map((message, index) => (
            <Message
              key={message.id || `msg-${index}`}
              message={message}
              isLast={index === displayMessages.length - 1}
            />
          ))
        )}
        
        {loading && (
          <div className="message-loading">
            <div className="message-loading-indicator">
              <div className="typing-indicator">
                <span></span>
                <span></span>
                <span></span>
              </div>
              <span className="loading-text">AI is thinking...</span>
            </div>
          </div>
        )}
        
        <div ref={messagesEndRef} />
      </div>
    </div>
  );
};

export default MessageList;
