import api from './api';

export const authService = {
  async login(username, password) {
    try {
      const response = await api.post('/auth/login', {
        username,
        password,
      });
      
      const { user, token } = response.data;
      
      // Store token and user data
      localStorage.setItem('authToken', token.access_token);
      localStorage.setItem('user', JSON.stringify(user));
      
      return { user, token };
    } catch (error) {
      throw new Error(
        error.response?.data?.message || 'Login failed'
      );
    }
  },

  async loginWithEmail(email, password) {
    try {
      const response = await api.post('/auth/login/email', {
        email,
        password,
      });
      
      const { user, token } = response.data;
      
      // Store token and user data
      localStorage.setItem('authToken', token.access_token);
      localStorage.setItem('user', JSON.stringify(user));
      
      return { user, token };
    } catch (error) {
      // Handle structured error responses
      if (error.response?.data?.detail && typeof error.response.data.detail === 'object') {
        const errorDetail = error.response.data.detail;
        const errorObj = new Error(errorDetail.message || 'Login failed');
        errorObj.errorType = errorDetail.error;
        errorObj.suggestions = errorDetail.suggestions;
        throw errorObj;
      }
      throw new Error(
        error.response?.data?.detail || error.response?.data?.message || 'Login failed'
      );
    }
  },

  async register(email, password, firstName, lastName) {
    try {
      const response = await api.post('/auth/register/email', {
        email,
        password,
        confirm_password: password,
        first_name: firstName,
        last_name: lastName,
      });
      
      const { user } = response.data;
      
      return { user };
    } catch (error) {
      throw new Error(
        error.response?.data?.detail || error.response?.data?.message || 'Registration failed'
      );
    }
  },

  async getGoogleOAuthUrl() {
    try {
      const response = await api.get('/auth/oauth/google/url');
      return response.data.url;
    } catch (error) {
      throw new Error(
        error.response?.data?.detail || 'Failed to get OAuth URL'
      );
    }
  },

  async isGoogleOAuthAvailable() {
    try {
      await api.get('/auth/oauth/google/url');
      return true;
    } catch (error) {
      // If we get a 503 Service Unavailable, OAuth is not configured
      if (error.response?.status === 503) {
        return false;
      }
      // For other errors, assume OAuth is available but there's a temporary issue
      return true;
    }
  },

  async handleGoogleOAuthCallback(code, redirectUri) {
    try {
      const response = await api.post('/auth/oauth/google', {
        code,
        redirect_uri: redirectUri,
      });
      
      const { user, token } = response.data;
      
      // Store token and user data
      localStorage.setItem('authToken', token.access_token);
      localStorage.setItem('user', JSON.stringify(user));
      
      return { user, token, isNewUser: response.data.is_new_user };
    } catch (error) {
      throw new Error(
        error.response?.data?.detail || 'OAuth authentication failed'
      );
    }
  },

  async requestPasswordReset(email) {
    try {
      const response = await api.post('/auth/password-reset', {
        email,
      });
      
      return response.data;
    } catch (error) {
      throw new Error(
        error.response?.data?.detail || 'Failed to request password reset'
      );
    }
  },

  async confirmPasswordReset(token, newPassword) {
    try {
      const response = await api.post('/auth/password-reset/confirm', {
        token,
        new_password: newPassword,
        confirm_password: newPassword,
      });
      
      return response.data;
    } catch (error) {
      throw new Error(
        error.response?.data?.detail || 'Failed to reset password'
      );
    }
  },

  async logout() {
    try {
      await api.post('/auth/logout');
    } catch (error) {
      // Continue with logout even if API call fails
      console.warn('Logout API call failed:', error);
    } finally {
      // Always clear local storage
      localStorage.removeItem('authToken');
      localStorage.removeItem('user');
    }
  },

  async getCurrentUser() {
    try {
      const response = await api.get('/auth/me');
      return response.data;
    } catch (error) {
      throw new Error(
        error.response?.data?.message || 'Failed to get user info'
      );
    }
  },

  async validateToken() {
    try {
      const response = await api.post('/auth/validate-token');
      return response.data;
    } catch (error) {
      return { valid: false };
    }
  },

  getStoredUser() {
    try {
      const user = localStorage.getItem('user');
      return user ? JSON.parse(user) : null;
    } catch (error) {
      return null;
    }
  },

  getStoredToken() {
    return localStorage.getItem('authToken');
  },

  isAuthenticated() {
    return !!this.getStoredToken();
  },
};
