"""
Authentication Service Module

This module provides comprehensive authentication services including:
- OAuth integration (Google)
- Email-based authentication
- Password reset functionality
- User registration and management
"""

import logging
import os
import secrets
import smtplib
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, Optional, Tuple

import bcrypt
import requests
from authlib.integrations.requests_client import OAuth2Session

from mini_llm_chat.backends.base import User
from mini_llm_chat.database_manager import get_database_manager

logger = logging.getLogger(__name__)


class AuthenticationService:
    """Comprehensive authentication service."""

    def __init__(self):
        """Initialize authentication service."""
        self.backend = get_database_manager().get_backend()
        
        # OAuth configuration
        self.google_client_id = os.getenv("GOOGLE_CLIENT_ID")
        self.google_client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
        
        # Email configuration
        self.smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_username = os.getenv("SMTP_USERNAME")
        self.smtp_password = os.getenv("SMTP_PASSWORD")
        self.from_email = os.getenv("FROM_EMAIL", self.smtp_username)
        
        # Application configuration
        self.app_name = os.getenv("APP_NAME", "Mini LLM Chat")
        self.app_url = os.getenv("APP_URL", "http://localhost:3000")

    def authenticate_with_email(self, email: str, password: str) -> Optional[User]:
        """
        Authenticate user with email and password.
        
        Args:
            email: User's email address
            password: User's password
            
        Returns:
            User object if authentication successful, None otherwise
        """
        try:
            session = self.backend._get_session()
            try:
                from mini_llm_chat.backends.postgresql import SQLAlchemyUser
                
                user = (
                    session.query(SQLAlchemyUser)
                    .filter(
                        SQLAlchemyUser.email == email,
                        SQLAlchemyUser.is_active.is_(True),
                    )
                    .first()
                )

                if user and user.hashed_password and bcrypt.checkpw(
                    password.encode("utf-8"), user.hashed_password.encode("utf-8")
                ):
                    # Update last login
                    user.last_login = datetime.utcnow()
                    session.commit()
                    session.refresh(user)
                    return self.backend._convert_user(user)
                return None
            finally:
                session.close()
        except Exception as e:
            logger.error(f"Email authentication error: {e}")
            return None

    def register_user(
        self, 
        email: str, 
        password: str, 
        first_name: str, 
        last_name: str
    ) -> Tuple[Optional[User], str]:
        """
        Register a new user with email and password.
        
        Args:
            email: User's email address
            password: User's password
            first_name: User's first name
            last_name: User's last name
            
        Returns:
            Tuple of (User object, error message). User is None if registration failed.
        """
        try:
            session = self.backend._get_session()
            try:
                from mini_llm_chat.backends.postgresql import SQLAlchemyUser
                
                # Check if user already exists
                existing_user = (
                    session.query(SQLAlchemyUser)
                    .filter(SQLAlchemyUser.email == email)
                    .first()
                )
                
                if existing_user:
                    return None, "User with this email already exists"
                
                # Generate username from email
                username = email.split('@')[0]
                counter = 1
                original_username = username
                
                # Ensure username is unique
                while session.query(SQLAlchemyUser).filter(
                    SQLAlchemyUser.username == username
                ).first():
                    username = f"{original_username}{counter}"
                    counter += 1
                
                # Create new user
                new_user = SQLAlchemyUser(
                    username=username,
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    role="user",
                    is_active=True,
                    email_verified=False
                )
                
                # Hash password
                salt = bcrypt.gensalt()
                new_user.hashed_password = bcrypt.hashpw(
                    password.encode("utf-8"), salt
                ).decode("utf-8")
                
                session.add(new_user)
                session.commit()
                session.refresh(new_user)
                
                logger.info(f"User registered successfully: {email}")
                return self.backend._convert_user(new_user), ""
                
            finally:
                session.close()
        except Exception as e:
            logger.error(f"User registration error: {e}")
            return None, f"Registration failed: {str(e)}"

    def authenticate_with_google(self, code: str, redirect_uri: str) -> Tuple[Optional[User], bool, str]:
        """
        Authenticate user with Google OAuth.
        
        Args:
            code: OAuth authorization code
            redirect_uri: OAuth redirect URI
            
        Returns:
            Tuple of (User object, is_new_user, error_message)
        """
        try:
            if not self.google_client_id or not self.google_client_secret:
                return None, False, "Google OAuth not configured"
            
            # Exchange code for token
            token_url = "https://oauth2.googleapis.com/token"
            token_data = {
                "client_id": self.google_client_id,
                "client_secret": self.google_client_secret,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
            }
            
            token_response = requests.post(token_url, data=token_data)
            token_response.raise_for_status()
            token_info = token_response.json()
            
            # Get user info from Google
            user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
            headers = {"Authorization": f"Bearer {token_info['access_token']}"}
            user_response = requests.get(user_info_url, headers=headers)
            user_response.raise_for_status()
            user_data = user_response.json()
            
            # Find or create user
            session = self.backend._get_session()
            try:
                from mini_llm_chat.backends.postgresql import SQLAlchemyUser
                
                # Check if user exists by email or OAuth ID
                existing_user = (
                    session.query(SQLAlchemyUser)
                    .filter(
                        (SQLAlchemyUser.email == user_data["email"]) |
                        (
                            (SQLAlchemyUser.oauth_provider == "google") &
                            (SQLAlchemyUser.oauth_id == user_data["id"])
                        )
                    )
                    .first()
                )
                
                if existing_user:
                    # Update OAuth info if needed
                    if not existing_user.oauth_provider:
                        existing_user.oauth_provider = "google"
                        existing_user.oauth_id = user_data["id"]
                        existing_user.email_verified = True
                    
                    # Update last login
                    existing_user.last_login = datetime.utcnow()
                    session.commit()
                    session.refresh(existing_user)
                    
                    return self.backend._convert_user(existing_user), False, ""
                
                # Create new user
                username = user_data["email"].split('@')[0]
                counter = 1
                original_username = username
                
                # Ensure username is unique
                while session.query(SQLAlchemyUser).filter(
                    SQLAlchemyUser.username == username
                ).first():
                    username = f"{original_username}{counter}"
                    counter += 1
                
                new_user = SQLAlchemyUser(
                    username=username,
                    email=user_data["email"],
                    first_name=user_data.get("given_name", ""),
                    last_name=user_data.get("family_name", ""),
                    role="user",
                    is_active=True,
                    oauth_provider="google",
                    oauth_id=user_data["id"],
                    email_verified=True,
                    hashed_password=None  # No password for OAuth users
                )
                
                session.add(new_user)
                session.commit()
                session.refresh(new_user)
                
                logger.info(f"New user created via Google OAuth: {user_data['email']}")
                return self.backend._convert_user(new_user), True, ""
                
            finally:
                session.close()
                
        except Exception as e:
            logger.error(f"Google OAuth authentication error: {e}")
            return None, False, f"OAuth authentication failed: {str(e)}"

    def initiate_password_reset(self, email: str) -> Tuple[bool, str]:
        """
        Initiate password reset process.
        
        Args:
            email: User's email address
            
        Returns:
            Tuple of (success, message)
        """
        try:
            session = self.backend._get_session()
            try:
                from mini_llm_chat.backends.postgresql import SQLAlchemyUser
                
                user = (
                    session.query(SQLAlchemyUser)
                    .filter(
                        SQLAlchemyUser.email == email,
                        SQLAlchemyUser.is_active.is_(True),
                    )
                    .first()
                )
                
                if not user:
                    # Don't reveal if user exists or not
                    return True, "If an account with this email exists, you will receive a password reset link."
                
                if user.oauth_provider:
                    return False, f"This account uses {user.oauth_provider} sign-in. Please use that method to log in."
                
                # Generate reset token
                reset_token = secrets.token_urlsafe(32)
                user.password_reset_token = reset_token
                user.password_reset_expires = datetime.utcnow() + timedelta(hours=1)
                
                session.commit()
                
                # Send reset email
                if self._send_password_reset_email(email, reset_token, user.first_name):
                    return True, "Password reset link sent to your email."
                else:
                    return False, "Failed to send password reset email. Please try again later."
                    
            finally:
                session.close()
                
        except Exception as e:
            logger.error(f"Password reset initiation error: {e}")
            return False, "Failed to initiate password reset. Please try again later."

    def reset_password(self, token: str, new_password: str) -> Tuple[bool, str]:
        """
        Reset user password with token.
        
        Args:
            token: Password reset token
            new_password: New password
            
        Returns:
            Tuple of (success, message)
        """
        try:
            session = self.backend._get_session()
            try:
                from mini_llm_chat.backends.postgresql import SQLAlchemyUser
                
                user = (
                    session.query(SQLAlchemyUser)
                    .filter(
                        SQLAlchemyUser.password_reset_token == token,
                        SQLAlchemyUser.password_reset_expires > datetime.utcnow(),
                        SQLAlchemyUser.is_active.is_(True),
                    )
                    .first()
                )
                
                if not user:
                    return False, "Invalid or expired reset token."
                
                # Hash new password
                salt = bcrypt.gensalt()
                user.hashed_password = bcrypt.hashpw(
                    new_password.encode("utf-8"), salt
                ).decode("utf-8")
                
                # Clear reset token
                user.password_reset_token = None
                user.password_reset_expires = None
                
                session.commit()
                
                logger.info(f"Password reset successful for user: {user.email}")
                return True, "Password reset successful. You can now log in with your new password."
                
            finally:
                session.close()
                
        except Exception as e:
            logger.error(f"Password reset error: {e}")
            return False, "Failed to reset password. Please try again."

    def _send_password_reset_email(self, email: str, token: str, first_name: str) -> bool:
        """
        Send password reset email.
        
        Args:
            email: User's email address
            token: Reset token
            first_name: User's first name
            
        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            if not all([self.smtp_username, self.smtp_password]):
                logger.warning("SMTP credentials not configured")
                return False
            
            reset_url = f"{self.app_url}/reset-password?token={token}"
            
            # Create email
            msg = MIMEMultipart()
            msg['From'] = self.from_email
            msg['To'] = email
            msg['Subject'] = f"Password Reset - {self.app_name}"
            
            # Email body
            body = f"""
Hello {first_name or 'there'},

You requested a password reset for your {self.app_name} account.

Click the link below to reset your password:
{reset_url}

This link will expire in 1 hour.

If you didn't request this password reset, please ignore this email.

Best regards,
The {self.app_name} Team
            """.strip()
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.smtp_username, self.smtp_password)
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Password reset email sent to: {email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send password reset email: {e}")
            return False

    def get_user_by_email(self, email: str) -> Optional[User]:
        """
        Get user by email address.
        
        Args:
            email: User's email address
            
        Returns:
            User object if found, None otherwise
        """
        try:
            session = self.backend._get_session()
            try:
                from mini_llm_chat.backends.postgresql import SQLAlchemyUser
                
                user = (
                    session.query(SQLAlchemyUser)
                    .filter(
                        SQLAlchemyUser.email == email,
                        SQLAlchemyUser.is_active.is_(True),
                    )
                    .first()
                )
                
                if user:
                    return self.backend._convert_user(user)
                return None
                
            finally:
                session.close()
                
        except Exception as e:
            logger.error(f"Error getting user by email: {e}")
            return None

    def get_google_oauth_url(self, redirect_uri: str) -> str:
        """
        Get Google OAuth authorization URL.
        
        Args:
            redirect_uri: OAuth redirect URI
            
        Returns:
            Authorization URL
        """
        if not self.google_client_id:
            raise ValueError("Google OAuth not configured")
        
        base_url = "https://accounts.google.com/o/oauth2/auth"
        params = {
            "client_id": self.google_client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid email profile",
            "response_type": "code",
            "access_type": "offline",
        }
        
        param_string = "&".join([f"{k}={v}" for k, v in params.items()])
        return f"{base_url}?{param_string}"


# Global authentication service instance
_auth_service = None


def get_auth_service() -> AuthenticationService:
    """Get the global authentication service instance."""
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthenticationService()
    return _auth_service
