import React from 'react';

const Message = ({ message, isLast }) => {
  const { role, content, streaming, created_at } = message;
  
  const formatTime = (timestamp) => {
    try {
      const date = new Date(timestamp);
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch (error) {
      return '';
    }
  };

  const formatContent = (text) => {
    // Simple formatting for line breaks
    return text.split('\n').map((line, index) => (
      <React.Fragment key={index}>
        {line}
        {index < text.split('\n').length - 1 && <br />}
      </React.Fragment>
    ));
  };

  return (
    <div className={`message message-${role}`}>
      <div className="message-content">
        <div className="message-header">
          <div className="message-role">
            {role === 'user' ? (
              <div className="message-avatar message-avatar-user">
                <span>You</span>
              </div>
            ) : (
              <div className="message-avatar message-avatar-assistant">
                <span>AI</span>
              </div>
            )}
          </div>
          {created_at && (
            <div className="message-time">
              {formatTime(created_at)}
            </div>
          )}
        </div>
        
        <div className="message-body">
          <div className={`message-text ${streaming ? 'message-streaming' : ''}`}>
            {formatContent(content)}
            {streaming && <span className="cursor">|</span>}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Message;
