import React, { useState, useEffect } from 'react';
import { Navigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import { authService } from '../../services/authService';
import Button from '../Common/Button';
import Input from '../Common/Input';

const LoginForm = () => {
  const { loginWithEmail, isAuthenticated, loading, error, clearError } = useAuth();
  const [searchParams] = useSearchParams();
  const [mode, setMode] = useState('email'); // 'email', 'register', 'forgot-password', 'reset-password'
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    firstName: '',
    lastName: '',
    confirmPassword: '',
  });
  const [formError, setFormError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [suggestions, setSuggestions] = useState([]);
  const [isGoogleOAuthAvailable, setIsGoogleOAuthAvailable] = useState(false);

  useEffect(() => {
    clearError();
    
    // Check if Google OAuth is available
    const checkOAuthAvailability = async () => {
      try {
        const available = await authService.isGoogleOAuthAvailable();
        setIsGoogleOAuthAvailable(available);
      } catch (error) {
        setIsGoogleOAuthAvailable(false);
      }
    };
    
    checkOAuthAvailability();
    
    // Handle OAuth callback
    const code = searchParams.get('code');
    if (code) {
      handleOAuthCallback(code);
    }

    // Handle password reset
    const resetToken = searchParams.get('token');
    if (resetToken) {
      setMode('reset-password');
    }
  }, [clearError, searchParams]);

  if (isAuthenticated) {
    return <Navigate to="/chat" replace />;
  }

  const handleOAuthCallback = async (code) => {
    try {
      const redirectUri = `${window.location.origin}${window.location.pathname}`;
      await authService.handleGoogleOAuthCallback(code, redirectUri);
      // The auth context will handle the redirect
    } catch (err) {
      setFormError(err.message);
    }
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value,
    }));
    
    // Clear errors when user starts typing
    if (formError) setFormError('');
    if (error) clearError();
    if (successMessage) setSuccessMessage('');
    if (suggestions.length > 0) setSuggestions([]);
  };

  const handleEmailLogin = async (e) => {
    e.preventDefault();
    
    if (!formData.email.trim()) {
      setFormError('Email is required');
      return;
    }
    
    if (!formData.password) {
      setFormError('Password is required');
      return;
    }

    try {
      await loginWithEmail(formData.email.trim(), formData.password);
    } catch (err) {
      setFormError(err.message);
      if (err.suggestions) {
        setSuggestions(err.suggestions);
      }
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    
    if (!formData.email.trim()) {
      setFormError('Email is required');
      return;
    }
    
    if (!formData.firstName.trim()) {
      setFormError('First name is required');
      return;
    }
    
    if (!formData.lastName.trim()) {
      setFormError('Last name is required');
      return;
    }
    
    if (!formData.password) {
      setFormError('Password is required');
      return;
    }
    
    if (formData.password !== formData.confirmPassword) {
      setFormError('Passwords do not match');
      return;
    }

    try {
      await authService.register(
        formData.email.trim(),
        formData.password,
        formData.firstName.trim(),
        formData.lastName.trim()
      );
      setSuccessMessage('Registration successful! You can now sign in.');
      setMode('email');
      setFormData({ ...formData, password: '', confirmPassword: '' });
    } catch (err) {
      setFormError(err.message);
    }
  };

  const handleForgotPassword = async (e) => {
    e.preventDefault();
    
    if (!formData.email.trim()) {
      setFormError('Email is required');
      return;
    }

    try {
      const response = await authService.requestPasswordReset(formData.email.trim());
      setSuccessMessage(response.message);
    } catch (err) {
      setFormError(err.message);
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    
    if (!formData.password) {
      setFormError('New password is required');
      return;
    }
    
    if (formData.password !== formData.confirmPassword) {
      setFormError('Passwords do not match');
      return;
    }

    try {
      const token = searchParams.get('token');
      const response = await authService.confirmPasswordReset(token, formData.password);
      setSuccessMessage(response.message);
      setMode('email');
      setFormData({ ...formData, password: '', confirmPassword: '' });
    } catch (err) {
      setFormError(err.message);
    }
  };

  const handleGoogleLogin = async () => {
    try {
      const oauthUrl = await authService.getGoogleOAuthUrl();
      window.location.href = oauthUrl;
    } catch (err) {
      setFormError(err.message);
    }
  };

  const displayError = formError || error;

  const renderEmailLoginForm = () => (
    <form onSubmit={handleEmailLogin} className="auth-form">
      <div className="form-group">
        <Input
          type="email"
          name="email"
          placeholder="Email address"
          value={formData.email}
          onChange={handleChange}
          disabled={loading}
          autoComplete="email"
          autoFocus
        />
      </div>

      <div className="form-group">
        <Input
          type="password"
          name="password"
          placeholder="Password"
          value={formData.password}
          onChange={handleChange}
          disabled={loading}
          autoComplete="current-password"
        />
      </div>

      <Button
        type="submit"
        disabled={loading || !formData.email.trim() || !formData.password}
        loading={loading}
        className="auth-button primary"
      >
        {loading ? 'Signing in...' : 'Sign In'}
      </Button>

      <div className="auth-links">
        <button
          type="button"
          onClick={() => setMode('forgot-password')}
          className="link-button"
        >
          Forgot your password?
        </button>
      </div>
    </form>
  );

  const renderRegisterForm = () => (
    <form onSubmit={handleRegister} className="auth-form">
      <div className="form-row">
        <div className="form-group">
          <Input
            type="text"
            name="firstName"
            placeholder="First name"
            value={formData.firstName}
            onChange={handleChange}
            disabled={loading}
            autoComplete="given-name"
          />
        </div>
        <div className="form-group">
          <Input
            type="text"
            name="lastName"
            placeholder="Last name"
            value={formData.lastName}
            onChange={handleChange}
            disabled={loading}
            autoComplete="family-name"
          />
        </div>
      </div>

      <div className="form-group">
        <Input
          type="email"
          name="email"
          placeholder="Email address"
          value={formData.email}
          onChange={handleChange}
          disabled={loading}
          autoComplete="email"
        />
      </div>

      <div className="form-group">
        <Input
          type="password"
          name="password"
          placeholder="Password"
          value={formData.password}
          onChange={handleChange}
          disabled={loading}
          autoComplete="new-password"
        />
      </div>

      <div className="form-group">
        <Input
          type="password"
          name="confirmPassword"
          placeholder="Confirm password"
          value={formData.confirmPassword}
          onChange={handleChange}
          disabled={loading}
          autoComplete="new-password"
        />
      </div>

      <Button
        type="submit"
        disabled={loading || !formData.email.trim() || !formData.firstName.trim() || 
                 !formData.lastName.trim() || !formData.password || !formData.confirmPassword}
        loading={loading}
        className="auth-button primary"
      >
        {loading ? 'Creating account...' : 'Create Account'}
      </Button>
    </form>
  );

  const renderForgotPasswordForm = () => (
    <form onSubmit={handleForgotPassword} className="auth-form">
      <div className="form-group">
        <Input
          type="email"
          name="email"
          placeholder="Email address"
          value={formData.email}
          onChange={handleChange}
          disabled={loading}
          autoComplete="email"
          autoFocus
        />
      </div>

      <Button
        type="submit"
        disabled={loading || !formData.email.trim()}
        loading={loading}
        className="auth-button primary"
      >
        {loading ? 'Sending...' : 'Send Reset Link'}
      </Button>

      <div className="auth-links">
        <button
          type="button"
          onClick={() => setMode('email')}
          className="link-button"
        >
          Back to sign in
        </button>
      </div>
    </form>
  );

  const renderResetPasswordForm = () => (
    <form onSubmit={handleResetPassword} className="auth-form">
      <div className="form-group">
        <Input
          type="password"
          name="password"
          placeholder="New password"
          value={formData.password}
          onChange={handleChange}
          disabled={loading}
          autoComplete="new-password"
          autoFocus
        />
      </div>

      <div className="form-group">
        <Input
          type="password"
          name="confirmPassword"
          placeholder="Confirm new password"
          value={formData.confirmPassword}
          onChange={handleChange}
          disabled={loading}
          autoComplete="new-password"
        />
      </div>

      <Button
        type="submit"
        disabled={loading || !formData.password || !formData.confirmPassword}
        loading={loading}
        className="auth-button primary"
      >
        {loading ? 'Resetting...' : 'Reset Password'}
      </Button>
    </form>
  );

  const getTitle = () => {
    switch (mode) {
      case 'register': return 'Create Account';
      case 'forgot-password': return 'Reset Password';
      case 'reset-password': return 'Set New Password';
      default: return 'Sign In';
    }
  };

  const getSubtitle = () => {
    switch (mode) {
      case 'register': return 'Join Mini LLM Chat';
      case 'forgot-password': return 'Enter your email to receive a reset link';
      case 'reset-password': return 'Enter your new password';
      default: return 'Welcome back';
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-header">
          <h1>Mini LLM Chat</h1>
          <h2>{getTitle()}</h2>
          <p>{getSubtitle()}</p>
        </div>

        {displayError && (
          <div className="error-message">
            {displayError}
            {suggestions.length > 0 && (
              <div className="error-suggestions">
                <p>Try:</p>
                <ul>
                  {suggestions.map((suggestion, index) => (
                    <li key={index}>{suggestion}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {successMessage && (
          <div className="success-message">
            {successMessage}
          </div>
        )}

        {mode === 'email' && renderEmailLoginForm()}
        {mode === 'register' && renderRegisterForm()}
        {mode === 'forgot-password' && renderForgotPasswordForm()}
        {mode === 'reset-password' && renderResetPasswordForm()}

        {(mode === 'email' || mode === 'register') && (
          <>
            {isGoogleOAuthAvailable && (
              <>
                <div className="auth-divider">
                  <span>or</span>
                </div>

                <Button
                  onClick={handleGoogleLogin}
                  disabled={loading}
                  className="auth-button google"
                >
                  <svg className="google-icon" viewBox="0 0 24 24">
                    <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                    <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                    <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                    <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                  </svg>
                  Continue with Google
                </Button>
              </>
            )}

            <div className="auth-switch">
              {mode === 'email' ? (
                <p>
                  Don't have an account?{' '}
                  <button
                    type="button"
                    onClick={() => setMode('register')}
                    className="link-button"
                  >
                    Sign up
                  </button>
                </p>
              ) : (
                <p>
                  Already have an account?{' '}
                  <button
                    type="button"
                    onClick={() => setMode('email')}
                    className="link-button"
                  >
                    Sign in
                  </button>
                </p>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
};

export default LoginForm;
