# Authentication System Guide

This guide covers the comprehensive authentication system implemented in Mini LLM Chat, including email/password authentication, Google OAuth, and password reset functionality.

## Features

### User Registration and Login
- **Email/Password Authentication**: Users can register and sign in with email and password
- **Google OAuth**: Users can sign up and sign in using their Google account
- **Production-ready Password Storage**: Uses bcrypt for secure password hashing
- **User Profile**: Stores first name, last name, and email for personalization

### Password Management
- **Password Reset**: Users can request password reset via email
- **Secure Reset Tokens**: Time-limited tokens for password reset (1 hour expiration)
- **Email Notifications**: Automated password reset emails

### Security Features
- **JWT Authentication**: Secure token-based authentication
- **Email Verification**: Track email verification status
- **OAuth Integration**: Secure Google OAuth 2.0 implementation
- **Error Handling**: Detailed error messages with helpful suggestions

## Configuration

### Environment Variables

Add these variables to your `.env` file:

```bash
# JWT Configuration
JWT_SECRET_KEY=your-secret-key-change-in-production

# Google OAuth Configuration (optional)
GOOGLE_CLIENT_ID=your_google_client_id_here
GOOGLE_CLIENT_SECRET=your_google_client_secret_here

# Email Configuration (for password reset)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password_here
FROM_EMAIL=your_email@gmail.com

# Application Configuration
APP_NAME=Mini LLM Chat
APP_URL=http://localhost:3000
```

### Google OAuth Setup

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API
4. Create OAuth 2.0 credentials
5. Add your domain to authorized origins
6. Add your callback URL: `http://localhost:3000/auth/oauth/google/callback`

### Email Configuration

For Gmail SMTP:
1. Enable 2-factor authentication on your Google account
2. Generate an App Password
3. Use the App Password as `SMTP_PASSWORD`

## Database Schema

The authentication system adds the following fields to the users table:

```sql
-- New fields added to users table
first_name VARCHAR(50)           -- User's first name
last_name VARCHAR(50)            -- User's last name
hashed_password VARCHAR(255)     -- Now nullable for OAuth users
oauth_provider VARCHAR(50)       -- 'google', etc.
oauth_id VARCHAR(100)           -- OAuth provider user ID
email_verified BOOLEAN          -- Email verification status
password_reset_token VARCHAR(255) -- Password reset token
password_reset_expires DATETIME   -- Token expiration time
```

## API Endpoints

### Authentication Routes

#### Email/Password Login
```http
POST /auth/login/email
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

#### User Registration
```http
POST /auth/register/email
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123",
  "confirm_password": "password123",
  "first_name": "John",
  "last_name": "Doe"
}
```

#### Google OAuth URL
```http
GET /auth/oauth/google/url
```

#### Google OAuth Callback
```http
POST /auth/oauth/google
Content-Type: application/json

{
  "code": "oauth_authorization_code",
  "redirect_uri": "http://localhost:3000/auth/oauth/google/callback"
}
```

#### Password Reset Request
```http
POST /auth/password-reset
Content-Type: application/json

{
  "email": "user@example.com"
}
```

#### Password Reset Confirmation
```http
POST /auth/password-reset/confirm
Content-Type: application/json

{
  "token": "reset_token",
  "new_password": "newpassword123",
  "confirm_password": "newpassword123"
}
```

## Frontend Integration

### Authentication Flow

The frontend provides a comprehensive authentication interface with:

1. **Sign In Form**: Email/password login
2. **Registration Form**: New user signup with name fields
3. **Google OAuth Button**: One-click Google sign-in
4. **Password Reset**: Forgot password functionality
5. **Error Handling**: User-friendly error messages with suggestions

### Usage Example

```javascript
import { authService } from './services/authService';

// Email/password login
try {
  const { user, token } = await authService.loginWithEmail(email, password);
  console.log('Logged in:', user);
} catch (error) {
  if (error.errorType === 'user_not_found') {
    // Show registration options
  } else if (error.errorType === 'invalid_password') {
    // Show password reset option
  }
}

// Google OAuth
try {
  const oauthUrl = await authService.getGoogleOAuthUrl();
  window.location.href = oauthUrl;
} catch (error) {
  console.error('OAuth error:', error);
}

// Password reset
try {
  await authService.requestPasswordReset(email);
  console.log('Reset email sent');
} catch (error) {
  console.error('Reset error:', error);
}
```

## User Experience

### Sign In Process

1. **Email Recognition**: System checks if email exists
2. **Smart Error Messages**: 
   - If email not found: Suggests registration options
   - If wrong password: Offers password reset
   - If OAuth account: Redirects to OAuth provider

### Registration Process

1. **Email/Password**: Traditional signup with name fields
2. **Google OAuth**: Automatic account creation from Google profile
3. **Welcome Messages**: Personalized greetings using first name

### Password Reset Process

1. **Request Reset**: User enters email address
2. **Email Sent**: Reset link sent to user's email
3. **Secure Reset**: Time-limited token validates reset request
4. **New Password**: User sets new password via secure form

## Security Considerations

### Password Security
- Minimum 8 characters with letters and numbers
- bcrypt hashing with salt
- Secure password reset tokens

### OAuth Security
- Secure state parameter handling
- Token validation
- Profile information verification

### Session Management
- JWT tokens with expiration
- Secure token storage
- Automatic token refresh

## Troubleshooting

### Common Issues

1. **Google OAuth Not Working**
   - Check client ID and secret
   - Verify redirect URI configuration
   - Ensure Google+ API is enabled

2. **Email Not Sending**
   - Verify SMTP credentials
   - Check firewall settings
   - Ensure app password is used for Gmail

3. **Database Errors**
   - Run database migrations
   - Check PostgreSQL connection
   - Verify table schema

### Error Messages

The system provides detailed error responses:

```json
{
  "error": "user_not_found",
  "message": "No account found with this email address.",
  "suggestions": [
    "Sign up with email and password",
    "Sign up with Google"
  ]
}
```

## Development

### Testing Authentication

1. **Local Development**: Use localhost URLs for OAuth
2. **Email Testing**: Use services like MailHog for local email testing
3. **Database**: Use PostgreSQL for full feature testing

### Adding New OAuth Providers

1. Add provider configuration to `auth_service.py`
2. Create new OAuth routes in `auth.py`
3. Update frontend with new OAuth buttons
4. Add provider-specific error handling

## Production Deployment

### Security Checklist

- [ ] Change JWT secret key
- [ ] Configure proper OAuth redirect URIs
- [ ] Set up production email service
- [ ] Enable HTTPS
- [ ] Configure CORS properly
- [ ] Set secure cookie flags
- [ ] Implement rate limiting
- [ ] Monitor authentication logs

### Environment Setup

1. **Database**: Ensure PostgreSQL is properly configured
2. **Email Service**: Use production email service (SendGrid, etc.)
3. **OAuth**: Configure production OAuth applications
4. **Monitoring**: Set up authentication monitoring and alerts

## Migration Guide

If upgrading from the previous authentication system:

1. **Backup Database**: Always backup before migration
2. **Run Migrations**: Apply new database schema
3. **Update Environment**: Add new environment variables
4. **Test Thoroughly**: Verify all authentication flows work
5. **Monitor**: Watch for any authentication issues post-deployment

The new system is backward compatible with existing username/password authentication while adding the new email-based features.
