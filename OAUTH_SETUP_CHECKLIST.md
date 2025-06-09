# Google OAuth Setup Checklist

Use this checklist to ensure your Google OAuth is properly configured.

## ✅ Google Cloud Console Setup

- [ ] Created Google Cloud project
- [ ] Enabled Google Identity/Google+ API
- [ ] Configured OAuth consent screen with:
  - [ ] App name: "Mini LLM Chat"
  - [ ] User support email
  - [ ] Scopes: email, profile, openid
  - [ ] Test users added (your email)
- [ ] Created OAuth 2.0 Client ID with:
  - [ ] Application type: Web application
  - [ ] Authorized JavaScript origins:
    - [ ] `http://localhost:3000`
    - [ ] `http://localhost:8000`
  - [ ] Authorized redirect URIs:
    - [ ] `http://localhost:3000/login`
    - [ ] `http://localhost:8000/auth/oauth/google/callback`
- [ ] Copied Client ID and Client Secret

## ✅ Environment Configuration

- [ ] Updated `.env` file with:
  - [ ] `GOOGLE_CLIENT_ID=your_actual_client_id`
  - [ ] `GOOGLE_CLIENT_SECRET=your_actual_client_secret`
  - [ ] `APP_NAME=Mini LLM Chat`
  - [ ] `APP_URL=http://localhost:3000`
  - [ ] `CORS_ORIGINS=http://localhost:3000,http://localhost:3001`

## ✅ Application Dependencies

- [ ] Backend dependencies installed:
  ```bash
  pip install authlib requests bcrypt
  ```
- [ ] Frontend dependencies installed:
  ```bash
  cd frontend && npm install
  ```

## ✅ Database Setup

- [ ] PostgreSQL database running
- [ ] Database migrations applied:
  ```bash
  alembic upgrade head
  ```
- [ ] Database connection working (check `DATABASE_URL` in `.env`)

## ✅ Testing

- [ ] Backend server starts without errors:
  ```bash
  python -m mini_llm_chat.web
  ```
- [ ] Frontend server starts without errors:
  ```bash
  cd frontend && npm start
  ```
- [ ] Can access login page at `http://localhost:3000`
- [ ] "Continue with Google" button appears
- [ ] OAuth flow works end-to-end:
  - [ ] Click Google button → redirects to Google
  - [ ] Sign in with Google → redirects back to app
  - [ ] User is logged in successfully

## ✅ Troubleshooting

If something doesn't work, check:

- [ ] Browser console for JavaScript errors
- [ ] Backend logs for Python errors
- [ ] Network tab for failed API calls
- [ ] Google Cloud Console for API quotas/limits
- [ ] Environment variables are loaded correctly

## 🚀 Ready to Go!

Once all items are checked, your Google OAuth is fully configured and ready for use!

## Quick Test Commands

```bash
# Start backend (from project root)
python -m mini_llm_chat.web

# Start frontend (in new terminal)
cd frontend && npm start

# Open browser
open http://localhost:3000
