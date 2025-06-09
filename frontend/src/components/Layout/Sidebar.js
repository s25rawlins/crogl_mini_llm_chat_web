import React from 'react';
import Button from '../Common/Button';

const Sidebar = ({
  conversations,
  currentConversation,
  onSelectConversation,
  onNewConversation,
  onDeleteConversation,
  isOpen
}) => {
  const formatDate = (timestamp) => {
    try {
      const date = new Date(timestamp);
      const now = new Date();
      const diffTime = Math.abs(now - date);
      const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
      
      if (diffDays === 1) {
        return 'Today';
      } else if (diffDays === 2) {
        return 'Yesterday';
      } else if (diffDays <= 7) {
        return `${diffDays - 1} days ago`;
      } else {
        return date.toLocaleDateString();
      }
    } catch (error) {
      return '';
    }
  };

  const truncateTitle = (title, maxLength = 30) => {
    if (title.length <= maxLength) return title;
    return title.substring(0, maxLength) + '...';
  };

  return (
    <aside className={`sidebar ${isOpen ? 'sidebar-open' : 'sidebar-closed'}`}>
      <div className="sidebar-header">
        <Button
          onClick={onNewConversation}
          variant="primary"
          size="small"
          className="new-chat-button"
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
            <line x1="12" y1="5" x2="12" y2="19"></line>
            <line x1="5" y1="12" x2="19" y2="12"></line>
          </svg>
          New Chat
        </Button>
      </div>

      <div className="sidebar-content">
        <div className="conversations-list">
          {conversations.length === 0 ? (
            <div className="conversations-empty">
              <p>No conversations yet</p>
              <p className="conversations-empty-hint">
                Start a new chat to begin
              </p>
            </div>
          ) : (
            conversations.map((conversation) => (
              <div
                key={conversation.id}
                className={`conversation-item ${
                  currentConversation?.id === conversation.id
                    ? 'conversation-item-active'
                    : ''
                }`}
              >
                <button
                  onClick={() => onSelectConversation(conversation.id)}
                  className="conversation-button"
                >
                  <div className="conversation-content">
                    <div className="conversation-title">
                      {truncateTitle(conversation.title)}
                    </div>
                    <div className="conversation-meta">
                      <span className="conversation-date">
                        {formatDate(conversation.updated_at)}
                      </span>
                      {conversation.message_count && (
                        <span className="conversation-count">
                          {conversation.message_count} messages
                        </span>
                      )}
                    </div>
                  </div>
                </button>
                
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    if (window.confirm('Are you sure you want to delete this conversation?')) {
                      onDeleteConversation(conversation.id);
                    }
                  }}
                  className="conversation-delete"
                  aria-label="Delete conversation"
                >
                  <svg
                    width="14"
                    height="14"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    <polyline points="3,6 5,6 21,6"></polyline>
                    <path d="M19,6v14a2,2 0 0,1 -2,2H7a2,2 0 0,1 -2,-2V6m3,0V4a2,2 0 0,1 2,-2h4a2,2 0 0,1 2,2v2"></path>
                    <line x1="10" y1="11" x2="10" y2="17"></line>
                    <line x1="14" y1="11" x2="14" y2="17"></line>
                  </svg>
                </button>
              </div>
            ))
          )}
        </div>
      </div>

      <div className="sidebar-footer">
        <div className="sidebar-info">
          <p className="sidebar-info-text">
            Mini LLM Chat v0.1.0
          </p>
          <p className="sidebar-info-subtext">
            Secure AI conversations
          </p>
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
