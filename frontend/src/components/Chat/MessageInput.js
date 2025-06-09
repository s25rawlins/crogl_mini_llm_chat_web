import React, { useState, useRef, useEffect } from 'react';
import Button from '../Common/Button';

const MessageInput = ({ onSendMessage, disabled, placeholder = "Type your message..." }) => {
  const [message, setMessage] = useState('');
  const textareaRef = useRef(null);

  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = `${textareaRef.current.scrollHeight}px`;
    }
  }, [message]);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (message.trim() && !disabled) {
      onSendMessage(message.trim());
      setMessage('');
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit(e);
    }
  };

  const handleChange = (e) => {
    setMessage(e.target.value);
  };

  return (
    <div className="message-input-container">
      <form onSubmit={handleSubmit} className="message-input-form">
        <div className="message-input-wrapper">
          <textarea
            ref={textareaRef}
            value={message}
            onChange={handleChange}
            onKeyDown={handleKeyDown}
            placeholder={placeholder}
            disabled={disabled}
            className="message-input-textarea"
            rows={1}
            maxLength={1000}
          />
          <Button
            type="submit"
            disabled={disabled || !message.trim()}
            className="message-send-button"
            variant="primary"
            size="small"
          >
            <svg
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <line x1="22" y1="2" x2="11" y2="13"></line>
              <polygon points="22,2 15,22 11,13 2,9"></polygon>
            </svg>
          </Button>
        </div>
        <div className="message-input-footer">
          <span className="message-input-hint">
            Press Enter to send, Shift+Enter for new line
          </span>
          <span className="message-input-counter">
            {message.length}/1000
          </span>
        </div>
      </form>
    </div>
  );
};

export default MessageInput;
