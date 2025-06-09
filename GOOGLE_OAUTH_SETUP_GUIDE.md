# Complete Google OAuth Setup Guide for Mini LLM Chat

This guide will walk you through setting up Google OAuth for your web application step by step, explaining every detail for beginners.

## What is OAuth?

OAuth (Open Authorization) is a secure way to let users sign in to your app using their existing Google account, without you having to handle their Google password. When a user clicks "Sign in with Google":

1. They're redirected to Google's secure login page
2. They enter their Google credentials on Google's site (not yours)
3. Google asks if they want to share basic info (name, email) with your app
4. If they agree, Google sends your app a special code
5. Your app exchanges this code for user information
6. You create an account for them or log them in

## Step 1: Create Google Cloud Project

### 1.1 Access Google Cloud Console
- Go to [Google Cloud Console](https://console.cloud.google.com/)
- Sign in with your Google account (create one if needed)

### 1.2 Create a New Project
- Click the project dropdown at the top of the page
- Click "New Project"
- Enter project details:
  - **Project name**: `mini-llm-chat-oauth` (or any name you prefer)
  - **Organization**: Leave as default (usually "No organization")
- Click "Create"
- Wait for the project to be created (usually takes a few seconds)

### 1.3 Select Your Project
- Make sure your new project is selected in the project dropdown
- You should see the project name in the top bar

## Step 2: Enable Required APIs

### 2.1 Navigate to APIs & Services
- In the left sidebar, click "APIs & Services"
- Click "Library"

### 2.2 Enable Google Identity Services
- In the search bar, type "Google Identity"
- Look for "Google Identity" or "Google+ API"
- Click on it and click "Enable"
- This allows your app to get user profile information

### 2.3 Enable OAuth2 API (if available)
- Search for "Google OAuth2 API"
- If found, click and enable it
- This provides the OAuth authentication functionality

## Step 3: Configure OAuth Consent Screen

### 3.1 Access Consent Screen Settings
- Go to "APIs & Services" → "OAuth consent screen"
- Choose "External" (unless you have Google Workspace)
- Click "Create"

### 3.2 Fill OAuth Consent Screen Information

**App Information:**
- **App name**: `Mini LLM Chat`
- **User support email**: Your email address
- **App logo**: Optional (you can upload later)

**App domain (Optional but recommended):**
- **Application home page**: `http://localhost:3000` (for development)
- **Application privacy policy link**: Leave blank for now
- **Application terms of service link**: Leave blank for now

**Authorized domains:**
- Add `localhost` for development
- Add your production domain when ready

**Developer contact information:**
- **Email addresses**: Your email address

Click "Save and Continue"

### 3.3 Configure Scopes
- Click "Add or Remove Scopes"
- Add these scopes:
  - `email` - to get user's email address
  - `profile` - to get user's name and profile picture
  - `openid` - for OpenID Connect authentication
- Click "Update" then "Save and Continue"

### 3.4 Add Test Users (Development Phase)
- Click "Add Users"
- Add your email address and any other emails you want to test with
- Click "Save and Continue"

### 3.5 Review and Submit
- Review your settings
- Click "Back to Dashboard"

## Step 4: Create OAuth 2.0 Credentials

### 4.1 Navigate to Credentials
- Go to "APIs & Services" → "Credentials"
- Click "Create Credentials"
- Select "OAuth 2.0 Client IDs"

### 4.2 Configure OAuth Client
**Application type:** Web application

**Name:** `Mini LLM Chat Web Client`

**Authorized JavaScript origins:**
Add these URLs (click "Add URI" for each):
- `http://localhost:3000` (your React frontend)
- `http://localhost:8000` (your Python backend)
- `http://127.0.0.1:3000` (alternative localhost)
- `http://127.0.0.1:8000` (alternative localhost)

**Authorized redirect URIs:**
Add these URLs (click "Add URI" for each):
- `http://localhost:3000/login` (frontend OAuth callback)
- `http://localhost:8000/auth/oauth/google/callback` (backend OAuth callback)

Click "Create"

### 4.3 Save Your Credentials
- A popup will show your credentials
- **Copy the Client ID** (looks like: `123456789-abcdefg.apps.googleusercontent.com`)
- **Copy the Client Secret** (looks like: `GOCSPX-abcdefghijklmnop`)
- Click "OK"

**IMPORTANT**: Keep these credentials secure! Never commit them to public repositories.

## Step 5: Configure Your Application

### 5.1 Update Environment Variables
Open your `.env` file and replace the placeholder values:

```bash
# Replace these with your actual Google OAuth credentials
GOOGLE_CLIENT_ID=123456789-abcdefg.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-abcdefghijklmnop
```

### 5.2 Verify Other Settings
Make sure these are set correctly in your `.env`:

```bash
# Application Configuration
APP_NAME=Mini LLM Chat
APP_URL=http://localhost:3000

# Web Interface Configuration
WEB_HOST=127.0.0.1
WEB_PORT=8000
CORS_ORIGINS=http://localhost:3000,http://localhost:3001
```

## Step 6: Test Your OAuth Setup

### 6.1 Start Your Backend Server
```bash
# From your project root directory
python -m mini_llm_chat.web
```

### 6.2 Start Your Frontend Server
```bash
# From the frontend directory
cd frontend
npm start
```

### 6.3 Test OAuth Flow
1. Open your browser to `http://localhost:3000`
2. You should see the login page
3. Click "Continue with Google" button
4. You should be redirected to Google's login page
5. Sign in with your Google account
6. Grant permissions to your app
7. You should be redirected back to your app and logged in

## Step 7: Troubleshooting Common Issues

### Issue: "OAuth client not found" error
**Solution**: Double-check your `GOOGLE_CLIENT_ID` in the `.env` file

### Issue: "Redirect URI mismatch" error
**Solution**: 
- Check that your redirect URIs in Google Cloud Console match exactly
- Make sure you're using the correct port numbers
- Verify the protocol (http vs https)

### Issue: "Access blocked" error
**Solution**: 
- Make sure you added your email as a test user in the OAuth consent screen
- Verify that the required APIs are enabled

### Issue: Google button doesn't appear
**Solution**: 
- Check browser console for JavaScript errors
- Verify that your backend is running and accessible
- Check that the OAuth availability check is working

### Issue: "This app isn't verified" warning
**Solution**: 
- This is normal for development
- Click "Advanced" then "Go to [your app] (unsafe)"
- For production, you'll need to verify your app with Google

## Step 8: Production Deployment

When you're ready to deploy to production:

### 8.1 Update OAuth Settings
- Add your production domain to "Authorized JavaScript origins"
- Add your production callback URLs to "Authorized redirect URIs"
- Update `APP_URL` in your production environment variables

### 8.2 Verify Your App (Optional)
- For public apps, consider going through Google's verification process
- This removes the "unverified app" warning for users

### 8.3 Security Best Practices
- Use environment variables for all secrets
- Never commit credentials to version control
- Use HTTPS in production
- Regularly rotate your client secret

## How the OAuth Flow Works in Your App

### Backend Flow:
1. User clicks "Continue with Google"
2. Frontend calls `/auth/oauth/google/url` to get Google's authorization URL
3. User is redirected to Google's login page
4. After login, Google redirects back with an authorization code
5. Frontend sends this code to `/auth/oauth/google` endpoint
6. Backend exchanges code for user information with Google
7. Backend creates/finds user account and returns JWT token
8. Frontend stores token and user is logged in

### Key Files in Your App:
- **Backend OAuth logic**: `mini_llm_chat/auth_service.py`
- **Backend OAuth routes**: `mini_llm_chat/web_api/routes/auth.py`
- **Frontend OAuth UI**: `frontend/src/components/Auth/LoginForm.js`
- **Frontend OAuth service**: `frontend/src/services/authService.js`

## Security Notes

### What Information Google Shares:
- Email address
- First and last name
- Profile picture URL
- Google user ID (unique identifier)

### What Your App Stores:
- User's email, name, and Google ID
- No passwords (OAuth users don't have passwords in your system)
- JWT tokens for session management

### Best Practices:
- Always use HTTPS in production
- Validate all data received from Google
- Implement proper session management
- Log security events for monitoring
- Keep your OAuth credentials secure

## Next Steps

After OAuth is working:
1. Test with multiple Google accounts
2. Implement proper error handling for edge cases
3. Add user profile management features
4. Consider adding other OAuth providers (GitHub, Microsoft, etc.)
5. Implement proper logging and monitoring
6. Plan for production deployment and scaling

Your OAuth implementation is now complete! Users can sign in with their Google accounts securely.
