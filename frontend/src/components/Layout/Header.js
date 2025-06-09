import React from 'react';
import { useAuth } from '../../hooks/useAuth';
import Button from '../Common/Button';

const Header = ({ user, onToggleSidebar, sidebarOpen }) => {
  const { logout } = useAuth();

  const handleLogout = async () => {
    try {
      await logout();
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  return (
    <header className="header">
      <div className="header-left">
        <Button
          onClick={onToggleSidebar}
          variant="ghost"
          size="small"
          className="sidebar-toggle"
          aria-label={sidebarOpen ? 'Close sidebar' : 'Open sidebar'}
        >
          <svg
            width="20"
            height="20"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <line x1="3" y1="6" x2="21" y2="6"></line>
            <line x1="3" y1="12" x2="21" y2="12"></line>
            <line x1="3" y1="18" x2="21" y2="18"></line>
          </svg>
        </Button>
        
        <div className="header-title">
          <h1>Mini LLM Chat</h1>
        </div>
      </div>

      <div className="header-right">
        <div className="user-info">
          <span className="user-name">{user?.first_name || user?.username}</span>
          {user?.is_admin && (
            <span className="user-badge">Admin</span>
          )}
        </div>
        
        <Button
          onClick={handleLogout}
          variant="ghost"
          size="small"
          className="logout-button"
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
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
            <polyline points="16,17 21,12 16,7"></polyline>
            <line x1="21" y1="12" x2="9" y2="12"></line>
          </svg>
          Logout
        </Button>
      </div>
    </header>
  );
};

export default Header;
