"""
Authentication Routes

This module contains FastAPI routes for user authentication,
including login, logout, registration, OAuth, and password reset.
"""

import logging
from typing import Dict, Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPAuthorizationCredentials

from mini_llm_chat.auth import (
    AuthenticationError,
    authenticate_user,
    create_admin_user,
    get_user_by_token,
)
from mini_llm_chat.auth_service import get_auth_service
from mini_llm_chat.backends.base import User
from mini_llm_chat.database_manager import get_database_manager
from mini_llm_chat.logging_hygiene import log_security_event
from mini_llm_chat.web_api.dependencies import get_current_user, security
from mini_llm_chat.web_api.models.auth import (
    AuthErrorResponse,
    ChangePasswordRequest,
    EmailLoginRequest,
    GoogleOAuthRequest,
    GoogleOAuthResponse,
    LoginRequest,
    LoginResponse,
    LogoutResponse,
    PasswordResetConfirmRequest,
    PasswordResetConfirmResponse,
    PasswordResetRequest,
    PasswordResetResponse,
    RegisterRequest,
    RegisterResponse,
    TokenResponse,
    TokenValidationResponse,
    UserResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/login", response_model=LoginResponse)
async def login(login_data: LoginRequest) -> LoginResponse:
    """
    Authenticate user and return JWT token.
    
    Args:
        login_data: Login credentials
        
    Returns:
        LoginResponse: User information and JWT token
        
    Raises:
        HTTPException: If authentication fails
    """
    try:
        # Authenticate user
        user = authenticate_user(login_data.username, login_data.password)
        
        if not user:
            logger.warning(f"Failed login attempt for username: {login_data.username}")
            log_security_event("login_failed", login_data.username, {"reason": "invalid_credentials"})
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        
        # Generate JWT token
        token = user.generate_token()
        
        # Log successful login
        logger.info(f"User {user.username} logged in successfully")
        log_security_event("login_success", user.username, {"user_id": user.id})
        
        # Create response models
        user_response = UserResponse(
            id=user.id,
            username=user.username,
            email=getattr(user, 'email', None),
            first_name=getattr(user, 'first_name', None),
            last_name=getattr(user, 'last_name', None),
            role=user.role,
            oauth_provider=getattr(user, 'oauth_provider', None),
            email_verified=getattr(user, 'email_verified', False),
            created_at=getattr(user, 'created_at', user.created_at),
            is_admin=user.is_admin()
        )
        
        token_response = TokenResponse(
            access_token=token,
            token_type="bearer"
        )
        
        return LoginResponse(
            user=user_response,
            token=token_response,
            message="Login successful"
        )
        
    except AuthenticationError as e:
        logger.warning(f"Authentication error for {login_data.username}: {e}")
        log_security_event("login_failed", login_data.username, {"reason": str(e)})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )
    except Exception as e:
        logger.error(f"Unexpected error during login for {login_data.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed due to server error"
        )


@router.post("/register", response_model=RegisterResponse)
async def register(register_data: RegisterRequest) -> RegisterResponse:
    """
    Register a new user account.
    
    Args:
        register_data: Registration information
        
    Returns:
        RegisterResponse: Created user information
        
    Raises:
        HTTPException: If registration fails
    """
    try:
        # Check if registration is allowed
        backend = get_database_manager().get_backend()
        backend_info = backend.get_backend_info()
        
        # For in-memory backend, only allow one user (session user)
        if backend_info["type"] == "memory":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Registration not available in demo mode"
            )
        
        # Create user account
        success = create_admin_user(
            register_data.username,
            register_data.email,
            register_data.password
        )
        
        if not success:
            logger.warning(f"Registration failed for username: {register_data.username}")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already exists"
            )
        
        # Get the created user
        user = authenticate_user(register_data.username, register_data.password)
        if not user:
            logger.error(f"Failed to retrieve user after registration: {register_data.username}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Registration completed but user retrieval failed"
            )
        
        logger.info(f"User {user.username} registered successfully")
        log_security_event("user_registered", user.username, {"user_id": user.id})
        
        user_response = UserResponse(
            id=user.id,
            username=user.username,
            email=getattr(user, 'email', None),
            first_name=getattr(user, 'first_name', None),
            last_name=getattr(user, 'last_name', None),
            role=user.role,
            oauth_provider=getattr(user, 'oauth_provider', None),
            email_verified=getattr(user, 'email_verified', False),
            created_at=getattr(user, 'created_at', user.created_at),
            is_admin=user.is_admin()
        )
        
        return RegisterResponse(
            user=user_response,
            message="Registration successful"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during registration for {register_data.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed due to server error"
        )


@router.post("/logout", response_model=LogoutResponse)
async def logout(current_user: User = Depends(get_current_user)) -> LogoutResponse:
    """
    Logout current user.
    
    Note: With JWT tokens, we can't truly invalidate them server-side
    without maintaining a blacklist. The client should discard the token.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        LogoutResponse: Logout confirmation
    """
    logger.info(f"User {current_user.username} logged out")
    log_security_event("logout", current_user.username, {"user_id": current_user.id})
    
    return LogoutResponse(message="Logout successful")


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)) -> UserResponse:
    """
    Get current user information.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        UserResponse: Current user information
    """
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        email=getattr(current_user, 'email', None),
        first_name=getattr(current_user, 'first_name', None),
        last_name=getattr(current_user, 'last_name', None),
        role=current_user.role,
        oauth_provider=getattr(current_user, 'oauth_provider', None),
        email_verified=getattr(current_user, 'email_verified', False),
        created_at=getattr(current_user, 'created_at', current_user.created_at),
        is_admin=current_user.is_admin()
    )


@router.post("/validate-token", response_model=TokenValidationResponse)
async def validate_token(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> TokenValidationResponse:
    """
    Validate a JWT token and return user information.
    
    Args:
        credentials: HTTP authorization credentials
        
    Returns:
        TokenValidationResponse: Token validation result
    """
    try:
        token = credentials.credentials
        user = get_user_by_token(token)
        
        if user:
            user_response = UserResponse(
                id=user.id,
                username=user.username,
                email=getattr(user, 'email', None),
                first_name=getattr(user, 'first_name', None),
                last_name=getattr(user, 'last_name', None),
                role=user.role,
                oauth_provider=getattr(user, 'oauth_provider', None),
                email_verified=getattr(user, 'email_verified', False),
                created_at=getattr(user, 'created_at', user.created_at),
                is_admin=user.is_admin()
            )
            
            return TokenValidationResponse(
                valid=True,
                user=user_response,
                message="Token is valid"
            )
        else:
            return TokenValidationResponse(
                valid=False,
                message="Token is invalid or expired"
            )
            
    except Exception as e:
        logger.warning(f"Token validation error: {e}")
        return TokenValidationResponse(
            valid=False,
            message="Token validation failed"
        )


@router.post("/change-password")
async def change_password(
    password_data: ChangePasswordRequest,
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Change user password.
    
    Args:
        password_data: Password change request
        current_user: Current authenticated user
        
    Returns:
        Dict: Success message
        
    Raises:
        HTTPException: If password change fails
    """
    try:
        # Verify current password
        if not current_user.verify_password(password_data.current_password):
            logger.warning(f"Invalid current password for user {current_user.username}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )
        
        # Update password
        current_user.set_password(password_data.new_password)
        
        # For persistent backends, we need to update the database
        backend = get_database_manager().get_backend()
        if hasattr(backend, '_get_session'):
            session = backend._get_session()
            try:
                from mini_llm_chat.backends.postgresql import SQLAlchemyUser
                
                db_user = session.query(SQLAlchemyUser).filter(
                    SQLAlchemyUser.id == current_user.id
                ).first()
                
                if db_user:
                    db_user.password_hash = current_user.password_hash
                    session.commit()
                    
            finally:
                session.close()
        
        logger.info(f"Password changed for user {current_user.username}")
        log_security_event("password_changed", current_user.username, {"user_id": current_user.id})
        
        return {"message": "Password changed successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error changing password for user {current_user.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password change failed due to server error"
        )


@router.post("/login/email", response_model=LoginResponse)
async def login_with_email(login_data: EmailLoginRequest) -> LoginResponse:
    """
    Authenticate user with email and password.
    
    Args:
        login_data: Email login credentials
        
    Returns:
        LoginResponse: User information and JWT token
        
    Raises:
        HTTPException: If authentication fails
    """
    try:
        auth_service = get_auth_service()
        user = auth_service.authenticate_with_email(login_data.email, login_data.password)
        
        if not user:
            # Check if user exists but with wrong password
            existing_user = auth_service.get_user_by_email(login_data.email)
            if existing_user:
                if existing_user.oauth_provider:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail={
                            "error": "oauth_account",
                            "message": f"This email is associated with a {existing_user.oauth_provider} account. Please sign in with {existing_user.oauth_provider}.",
                            "suggestions": [f"Sign in with {existing_user.oauth_provider}"]
                        }
                    )
                else:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail={
                            "error": "invalid_password",
                            "message": "The email and password combination is incorrect.",
                            "suggestions": [
                                "Check your password and try again",
                                "Reset your password if you've forgotten it"
                            ]
                        }
                    )
            else:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail={
                        "error": "user_not_found",
                        "message": "No account found with this email address.",
                        "suggestions": [
                            "Sign up with email and password",
                            "Sign up with Google"
                        ]
                    }
                )
        
        # Generate JWT token
        token = user.generate_token()
        
        # Log successful login
        logger.info(f"User {user.username} logged in with email successfully")
        log_security_event("email_login_success", user.username, {"user_id": user.id})
        
        # Create response models
        user_response = UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            role=user.role,
            oauth_provider=user.oauth_provider,
            email_verified=user.email_verified,
            created_at=user.created_at,
            is_admin=user.is_admin()
        )
        
        token_response = TokenResponse(
            access_token=token,
            token_type="bearer"
        )
        
        return LoginResponse(
            user=user_response,
            token=token_response,
            message=f"Welcome back, {user.first_name or user.username}!"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during email login for {login_data.email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed due to server error"
        )


@router.post("/register/email", response_model=RegisterResponse)
async def register_with_email(register_data: RegisterRequest) -> RegisterResponse:
    """
    Register a new user with email and password.
    
    Args:
        register_data: Registration information
        
    Returns:
        RegisterResponse: Created user information
        
    Raises:
        HTTPException: If registration fails
    """
    try:
        # Check if registration is allowed
        backend = get_database_manager().get_backend()
        backend_info = backend.get_backend_info()
        
        # For in-memory backend, only allow one user (session user)
        if backend_info["type"] == "memory":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Registration not available in demo mode"
            )
        
        auth_service = get_auth_service()
        user, error_message = auth_service.register_user(
            register_data.email,
            register_data.password,
            register_data.first_name,
            register_data.last_name
        )
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=error_message
            )
        
        logger.info(f"User {user.email} registered successfully")
        log_security_event("user_registered", user.username, {"user_id": user.id})
        
        user_response = UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            role=user.role,
            oauth_provider=user.oauth_provider,
            email_verified=user.email_verified,
            created_at=user.created_at,
            is_admin=user.is_admin()
        )
        
        return RegisterResponse(
            user=user_response,
            message=f"Welcome to {auth_service.app_name}, {user.first_name}!"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during registration for {register_data.email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed due to server error"
        )


@router.get("/oauth/google/url")
async def get_google_oauth_url(request: Request) -> Dict[str, str]:
    """
    Get Google OAuth authorization URL.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Dict containing the OAuth URL
        
    Raises:
        HTTPException: If OAuth is not configured
    """
    try:
        auth_service = get_auth_service()
        
        # Construct redirect URI
        base_url = str(request.base_url).rstrip('/')
        redirect_uri = f"{base_url}/auth/oauth/google/callback"
        
        oauth_url = auth_service.get_google_oauth_url(redirect_uri)
        
        return {"url": oauth_url}
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Error generating Google OAuth URL: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate OAuth URL"
        )


@router.post("/oauth/google", response_model=GoogleOAuthResponse)
async def google_oauth_callback(oauth_data: GoogleOAuthRequest) -> GoogleOAuthResponse:
    """
    Handle Google OAuth callback.
    
    Args:
        oauth_data: OAuth callback data
        
    Returns:
        GoogleOAuthResponse: User information and JWT token
        
    Raises:
        HTTPException: If OAuth authentication fails
    """
    try:
        auth_service = get_auth_service()
        user, is_new_user, error_message = auth_service.authenticate_with_google(
            oauth_data.code, oauth_data.redirect_uri
        )
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_message
            )
        
        # Generate JWT token
        token = user.generate_token()
        
        # Log successful login
        action = "google_oauth_register" if is_new_user else "google_oauth_login"
        logger.info(f"User {user.username} authenticated via Google OAuth (new_user: {is_new_user})")
        log_security_event(action, user.username, {"user_id": user.id})
        
        # Create response models
        user_response = UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            role=user.role,
            oauth_provider=user.oauth_provider,
            email_verified=user.email_verified,
            created_at=user.created_at,
            is_admin=user.is_admin()
        )
        
        token_response = TokenResponse(
            access_token=token,
            token_type="bearer"
        )
        
        welcome_message = (
            f"Welcome to {auth_service.app_name}, {user.first_name}!" if is_new_user
            else f"Welcome back, {user.first_name}!"
        )
        
        return GoogleOAuthResponse(
            user=user_response,
            token=token_response,
            is_new_user=is_new_user,
            message=welcome_message
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during Google OAuth: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OAuth authentication failed due to server error"
        )


@router.post("/password-reset", response_model=PasswordResetResponse)
async def request_password_reset(reset_data: PasswordResetRequest) -> PasswordResetResponse:
    """
    Request password reset for user.
    
    Args:
        reset_data: Password reset request data
        
    Returns:
        PasswordResetResponse: Reset instructions
    """
    try:
        auth_service = get_auth_service()
        success, message = auth_service.initiate_password_reset(reset_data.email)
        
        return PasswordResetResponse(
            message=message,
            email_sent=success
        )
        
    except Exception as e:
        logger.error(f"Error initiating password reset for {reset_data.email}: {e}")
        return PasswordResetResponse(
            message="Failed to process password reset request. Please try again later.",
            email_sent=False
        )


@router.post("/password-reset/confirm", response_model=PasswordResetConfirmResponse)
async def confirm_password_reset(reset_data: PasswordResetConfirmRequest) -> PasswordResetConfirmResponse:
    """
    Confirm password reset with token.
    
    Args:
        reset_data: Password reset confirmation data
        
    Returns:
        PasswordResetConfirmResponse: Reset confirmation
        
    Raises:
        HTTPException: If reset fails
    """
    try:
        auth_service = get_auth_service()
        success, message = auth_service.reset_password(reset_data.token, reset_data.new_password)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=message
            )
        
        return PasswordResetConfirmResponse(message=message)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error confirming password reset: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reset password. Please try again."
        )
