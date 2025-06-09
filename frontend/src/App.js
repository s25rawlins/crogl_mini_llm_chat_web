import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './hooks/useAuth';
import AuthGuard from './components/Auth/AuthGuard';
import LoginForm from './components/Auth/LoginForm';
import ChatContainer from './components/Chat/ChatContainer';
import './styles/components.css';

function App() {
  return (
    <AuthProvider>
      <Router>
        <div className="app">
          <Routes>
            <Route path="/login" element={<LoginForm />} />
            <Route 
              path="/chat" 
              element={
                <AuthGuard>
                  <ChatContainer />
                </AuthGuard>
              } 
            />
            <Route path="/" element={<Navigate to="/chat" replace />} />
          </Routes>
        </div>
      </Router>
    </AuthProvider>
  );
}

export default App;
