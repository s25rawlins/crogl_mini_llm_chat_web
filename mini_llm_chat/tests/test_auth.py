"""
Authentication Tests Module

This module contains comprehensive unit tests for the authentication functionality.
It tests user login, token management, authorization, and admin setup.
"""

import os
from unittest.mock import MagicMock, mock_open, patch

import pytest

from mini_llm_chat.auth import (
    AuthenticationError,
    AuthorizationError,
    check_permissions,
    get_auth_from_env,
    interactive_auth,
    login_user,
    login_with_token,
    logout_user,
    require_admin,
    save_token_to_env_file,
    setup_initial_admin,
)
from mini_llm_chat.database import User


class TestAuthenticationError:
    """Test cases for AuthenticationError exception."""

    def test_authentication_error_creation(self):
        """Test creating AuthenticationError."""
        error = AuthenticationError("Test error")
        assert str(error) == "Test error"


class TestAuthorizationError:
    """Test cases for AuthorizationError exception."""

    def test_authorization_error_creation(self):
        """Test creating AuthorizationError."""
        error = AuthorizationError("Test error")
        assert str(error) == "Test error"


class TestLoginUser:
    """Test cases for login_user function."""

    @patch("mini_llm_chat.auth.authenticate_user")
    @patch("getpass.getpass")
    @patch("builtins.input")
    @patch("builtins.print")
    def test_login_user_success(
        self, mock_print, mock_input, mock_getpass, mock_authenticate
    ):
        """Test successful user login."""
        # Mock user input
        mock_input.return_value = "testuser"
        mock_getpass.return_value = "password123"

        # Mock successful authentication
        mock_user = User(
            id=1, username="testuser", email="test@example.com", role="user"
        )
        mock_user.generate_token = MagicMock(return_value="test.jwt.token")
        mock_authenticate.return_value = mock_user

        user, token = login_user()

        assert user == mock_user
        assert token == "test.jwt.token"
        mock_authenticate.assert_called_once_with("testuser", "password123")

    @patch("mini_llm_chat.auth.authenticate_user")
    @patch("getpass.getpass")
    @patch("builtins.input")
    @patch("builtins.print")
    def test_login_user_invalid_credentials(
        self, mock_print, mock_input, mock_getpass, mock_authenticate
    ):
        """Test login with invalid credentials."""
        # Mock user input
        mock_input.return_value = "testuser"
        mock_getpass.return_value = "wrongpassword"

        # Mock failed authentication (3 attempts)
        mock_authenticate.return_value = None

        with pytest.raises(
            AuthenticationError, match="Authentication failed after maximum attempts"
        ):
            login_user()

        assert mock_authenticate.call_count == 3  # Should try 3 times

    @patch("getpass.getpass")
    @patch("builtins.input")
    @patch("builtins.print")
    def test_login_user_empty_username(self, mock_print, mock_input, mock_getpass):
        """Test login with empty username."""
        # Mock empty username, then valid username
        mock_input.side_effect = ["", "testuser"]
        mock_getpass.return_value = "password123"

        with patch("mini_llm_chat.auth.authenticate_user") as mock_authenticate:
            mock_user = User(
                id=1, username="testuser", email="test@example.com", role="user"
            )
            mock_user.generate_token = MagicMock(return_value="test.jwt.token")
            mock_authenticate.return_value = mock_user

            user, token = login_user()

            assert user == mock_user
            # Should have been called twice due to empty username first
            assert mock_input.call_count == 2

    @patch("getpass.getpass")
    @patch("builtins.input")
    @patch("builtins.print")
    def test_login_user_empty_password(self, mock_print, mock_input, mock_getpass):
        """Test login with empty password."""
        mock_input.return_value = "testuser"
        # Mock empty password, then valid password
        mock_getpass.side_effect = ["", "password123"]

        with patch("mini_llm_chat.auth.authenticate_user") as mock_authenticate:
            mock_user = User(
                id=1, username="testuser", email="test@example.com", role="user"
            )
            mock_user.generate_token = MagicMock(return_value="test.jwt.token")
            mock_authenticate.return_value = mock_user

            user, token = login_user()

            assert user == mock_user
            # Should have been called twice due to empty password first
            assert mock_getpass.call_count == 2

    @patch("builtins.input")
    @patch("builtins.print")
    def test_login_user_keyboard_interrupt(self, mock_print, mock_input):
        """Test login cancelled by user."""
        mock_input.side_effect = KeyboardInterrupt()

        with pytest.raises(AuthenticationError, match="Login cancelled by user"):
            login_user()

    @patch("mini_llm_chat.auth.authenticate_user")
    @patch("getpass.getpass")
    @patch("builtins.input")
    @patch("builtins.print")
    def test_login_user_exception_during_auth(
        self, mock_print, mock_input, mock_getpass, mock_authenticate
    ):
        """Test login with exception during authentication."""
        mock_input.return_value = "testuser"
        mock_getpass.return_value = "password123"

        # Mock authentication to raise exception 3 times
        mock_authenticate.side_effect = [Exception("Database error")] * 3

        with pytest.raises(
            AuthenticationError, match="Authentication failed after maximum attempts"
        ):
            login_user()


class TestLoginWithToken:
    """Test cases for login_with_token function."""

    @patch("mini_llm_chat.auth.get_user_by_token")
    def test_login_with_token_success(self, mock_get_user):
        """Test successful token authentication."""
        mock_user = User(
            id=1, username="testuser", email="test@example.com", role="user"
        )
        mock_get_user.return_value = mock_user

        result = login_with_token("valid.jwt.token")

        assert result == mock_user
        mock_get_user.assert_called_once_with("valid.jwt.token")

    @patch("mini_llm_chat.auth.get_user_by_token")
    def test_login_with_token_invalid(self, mock_get_user):
        """Test token authentication with invalid token."""
        mock_get_user.return_value = None

        result = login_with_token("invalid.token")

        assert result is None

    @patch("mini_llm_chat.auth.get_user_by_token")
    def test_login_with_token_exception(self, mock_get_user):
        """Test token authentication with exception."""
        mock_get_user.side_effect = Exception("Database error")

        result = login_with_token("some.token")

        assert result is None


class TestRequireAdmin:
    """Test cases for require_admin function."""

    def test_require_admin_success(self):
        """Test require_admin with admin user."""
        admin_user = User(username="admin", email="admin@example.com", role="admin")

        # Should not raise exception
        require_admin(admin_user)

    def test_require_admin_failure(self):
        """Test require_admin with non-admin user."""
        regular_user = User(username="user", email="user@example.com", role="user")

        with pytest.raises(AuthorizationError, match="Admin privileges required"):
            require_admin(regular_user)


class TestSetupInitialAdmin:
    """Test cases for setup_initial_admin function."""

    @patch("mini_llm_chat.auth.create_admin_user")
    @patch("getpass.getpass")
    @patch("builtins.input")
    @patch("builtins.print")
    def test_setup_initial_admin_success(
        self, mock_print, mock_input, mock_getpass, mock_create_admin
    ):
        """Test successful admin setup."""
        # Mock user input
        mock_input.side_effect = ["admin", "admin@example.com"]
        mock_getpass.side_effect = [
            "password123",
            "password123",
        ]  # Password and confirmation

        # Mock successful admin creation
        mock_create_admin.return_value = True

        result = setup_initial_admin()

        assert result is True
        mock_create_admin.assert_called_once_with(
            "admin", "admin@example.com", "password123"
        )

    @patch("mini_llm_chat.auth.create_admin_user")
    @patch("getpass.getpass")
    @patch("builtins.input")
    @patch("builtins.print")
    def test_setup_initial_admin_already_exists(
        self, mock_print, mock_input, mock_getpass, mock_create_admin
    ):
        """Test admin setup when admin already exists."""
        mock_input.side_effect = ["admin", "admin@example.com"]
        mock_getpass.side_effect = ["password123", "password123"]

        # Mock admin already exists
        mock_create_admin.return_value = False

        result = setup_initial_admin()

        assert result is False

    @patch("builtins.input")
    @patch("builtins.print")
    def test_setup_initial_admin_empty_username(self, mock_print, mock_input):
        """Test admin setup with empty username."""
        mock_input.return_value = ""

        result = setup_initial_admin()

        assert result is False

    @patch("builtins.input")
    @patch("builtins.print")
    def test_setup_initial_admin_empty_email(self, mock_print, mock_input):
        """Test admin setup with empty email."""
        mock_input.side_effect = ["admin", ""]

        result = setup_initial_admin()

        assert result is False

    @patch("getpass.getpass")
    @patch("builtins.input")
    @patch("builtins.print")
    def test_setup_initial_admin_empty_password(
        self, mock_print, mock_input, mock_getpass
    ):
        """Test admin setup with empty password."""
        mock_input.side_effect = ["admin", "admin@example.com"]
        mock_getpass.return_value = ""

        result = setup_initial_admin()

        assert result is False

    @patch("getpass.getpass")
    @patch("builtins.input")
    @patch("builtins.print")
    def test_setup_initial_admin_password_mismatch(
        self, mock_print, mock_input, mock_getpass
    ):
        """Test admin setup with password mismatch."""
        mock_input.side_effect = ["admin", "admin@example.com"]
        mock_getpass.side_effect = ["password123", "different_password"]

        result = setup_initial_admin()

        assert result is False

    @patch("builtins.input")
    @patch("builtins.print")
    def test_setup_initial_admin_keyboard_interrupt(self, mock_print, mock_input):
        """Test admin setup cancelled by user."""
        mock_input.side_effect = KeyboardInterrupt()

        result = setup_initial_admin()

        assert result is False

    @patch("mini_llm_chat.auth.create_admin_user")
    @patch("getpass.getpass")
    @patch("builtins.input")
    @patch("builtins.print")
    def test_setup_initial_admin_exception(
        self, mock_print, mock_input, mock_getpass, mock_create_admin
    ):
        """Test admin setup with exception."""
        mock_input.side_effect = ["admin", "admin@example.com"]
        mock_getpass.side_effect = ["password123", "password123"]
        mock_create_admin.side_effect = Exception("Database error")

        result = setup_initial_admin()

        assert result is False


class TestGetAuthFromEnv:
    """Test cases for get_auth_from_env function."""

    @patch.dict(os.environ, {"MINI_LLM_CHAT_TOKEN": "test.jwt.token"})
    def test_get_auth_from_env_exists(self):
        """Test getting auth token from environment when it exists."""
        result = get_auth_from_env()
        assert result == "test.jwt.token"

    @patch.dict(os.environ, {}, clear=True)
    def test_get_auth_from_env_not_exists(self):
        """Test getting auth token from environment when it doesn't exist."""
        result = get_auth_from_env()
        assert result is None


class TestSaveTokenToEnvFile:
    """Test cases for save_token_to_env_file function."""

    @patch(
        "builtins.open", new_callable=mock_open, read_data="OPENAI_API_KEY=sk-test\n"
    )
    @patch("os.path.exists")
    def test_save_token_to_env_file_new_file(self, mock_exists, mock_file):
        """Test saving token to new env file."""
        mock_exists.return_value = False

        result = save_token_to_env_file("test.jwt.token")

        assert result is True
        mock_file.assert_called()

    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data="OPENAI_API_KEY=sk-test\nOTHER_VAR=value\n",
    )
    @patch("os.path.exists")
    def test_save_token_to_env_file_existing_file(self, mock_exists, mock_file):
        """Test saving token to existing env file."""
        mock_exists.return_value = True

        result = save_token_to_env_file("test.jwt.token")

        assert result is True
        # Should read and write
        assert mock_file.call_count >= 2

    @patch("builtins.open")
    @patch("os.path.exists")
    def test_save_token_to_env_file_exception(self, mock_exists, mock_file):
        """Test saving token with file exception."""
        mock_exists.return_value = False
        mock_file.side_effect = Exception("File error")

        result = save_token_to_env_file("test.jwt.token")

        assert result is False


class TestInteractiveAuth:
    """Test cases for interactive_auth function."""

    @patch("mini_llm_chat.auth.save_token_to_env_file")
    @patch("mini_llm_chat.auth.login_user")
    @patch("mini_llm_chat.auth.login_with_token")
    @patch("mini_llm_chat.auth.get_auth_from_env")
    @patch("builtins.input")
    @patch("builtins.print")
    def test_interactive_auth_existing_valid_token(
        self,
        mock_print,
        mock_input,
        mock_get_env,
        mock_login_token,
        mock_login_user,
        mock_save_token,
    ):
        """Test interactive auth with existing valid token."""
        # Mock existing token
        mock_get_env.return_value = "existing.jwt.token"

        # Mock successful token login
        mock_user = User(
            id=1, username="testuser", email="test@example.com", role="user"
        )
        mock_login_token.return_value = mock_user

        user, token = interactive_auth()

        assert user == mock_user
        assert token == "existing.jwt.token"
        mock_login_user.assert_not_called()  # Should not prompt for login

    @patch("mini_llm_chat.auth.save_token_to_env_file")
    @patch("mini_llm_chat.auth.login_user")
    @patch("mini_llm_chat.auth.login_with_token")
    @patch("mini_llm_chat.auth.get_auth_from_env")
    @patch("builtins.input")
    @patch("builtins.print")
    def test_interactive_auth_existing_invalid_token(
        self,
        mock_print,
        mock_input,
        mock_get_env,
        mock_login_token,
        mock_login_user,
        mock_save_token,
    ):
        """Test interactive auth with existing invalid token."""
        # Mock existing but invalid token
        mock_get_env.return_value = "invalid.jwt.token"
        mock_login_token.return_value = None

        # Mock successful interactive login
        mock_user = User(
            id=1, username="testuser", email="test@example.com", role="user"
        )
        mock_login_user.return_value = (mock_user, "new.jwt.token")

        # Mock user chooses not to save token
        mock_input.return_value = "n"

        user, token = interactive_auth()

        assert user == mock_user
        assert token == "new.jwt.token"
        mock_login_user.assert_called_once()
        mock_save_token.assert_not_called()

    @patch("mini_llm_chat.auth.save_token_to_env_file")
    @patch("mini_llm_chat.auth.login_user")
    @patch("mini_llm_chat.auth.get_auth_from_env")
    @patch("builtins.input")
    @patch("builtins.print")
    def test_interactive_auth_no_existing_token_save_yes(
        self, mock_print, mock_input, mock_get_env, mock_login_user, mock_save_token
    ):
        """Test interactive auth with no existing token, user chooses to save."""
        # Mock no existing token
        mock_get_env.return_value = None

        # Mock successful interactive login
        mock_user = User(
            id=1, username="testuser", email="test@example.com", role="user"
        )
        mock_login_user.return_value = (mock_user, "new.jwt.token")

        # Mock user chooses to save token
        mock_input.return_value = "y"
        mock_save_token.return_value = True

        user, token = interactive_auth()

        assert user == mock_user
        assert token == "new.jwt.token"
        mock_save_token.assert_called_once_with("new.jwt.token")

    @patch("mini_llm_chat.auth.save_token_to_env_file")
    @patch("mini_llm_chat.auth.login_user")
    @patch("mini_llm_chat.auth.get_auth_from_env")
    @patch("builtins.input")
    @patch("builtins.print")
    def test_interactive_auth_save_token_fails(
        self, mock_print, mock_input, mock_get_env, mock_login_user, mock_save_token
    ):
        """Test interactive auth when saving token fails."""
        mock_get_env.return_value = None

        mock_user = User(
            id=1, username="testuser", email="test@example.com", role="user"
        )
        mock_login_user.return_value = (mock_user, "new.jwt.token")

        # Mock user chooses to save token but it fails
        mock_input.return_value = "yes"
        mock_save_token.return_value = False

        user, token = interactive_auth()

        assert user == mock_user
        assert token == "new.jwt.token"


class TestCheckPermissions:
    """Test cases for check_permissions function."""

    def test_check_permissions_admin_required_admin_user(self):
        """Test permission check for admin requirement with admin user."""
        admin_user = User(username="admin", email="admin@example.com", role="admin")

        result = check_permissions(admin_user, "admin")

        assert result is True

    def test_check_permissions_admin_required_regular_user(self):
        """Test permission check for admin requirement with regular user."""
        regular_user = User(username="user", email="user@example.com", role="user")

        result = check_permissions(regular_user, "admin")

        assert result is False

    def test_check_permissions_user_required_admin_user(self):
        """Test permission check for user requirement with admin user."""
        admin_user = User(username="admin", email="admin@example.com", role="admin")

        result = check_permissions(admin_user, "user")

        assert result is True

    def test_check_permissions_user_required_regular_user(self):
        """Test permission check for user requirement with regular user."""
        regular_user = User(username="user", email="user@example.com", role="user")

        result = check_permissions(regular_user, "user")

        assert result is True

    def test_check_permissions_unknown_role(self):
        """Test permission check with unknown role requirement."""
        user = User(username="user", email="user@example.com", role="user")

        result = check_permissions(user, "unknown_role")

        assert result is False


class TestLogoutUser:
    """Test cases for logout_user function."""

    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data="OPENAI_API_KEY=sk-test\nMINI_LLM_CHAT_TOKEN=old.token\nOTHER_VAR=value\n",
    )
    @patch("os.path.exists")
    def test_logout_user_success(self, mock_exists, mock_file):
        """Test successful user logout."""
        mock_exists.return_value = True

        result = logout_user("old.token")

        assert result is True
        # Should read and write the file
        assert mock_file.call_count >= 2

    @patch("os.path.exists")
    def test_logout_user_no_env_file(self, mock_exists):
        """Test logout when no env file exists."""
        mock_exists.return_value = False

        result = logout_user("some.token")

        assert result is True  # Should still succeed

    @patch("builtins.open")
    @patch("os.path.exists")
    def test_logout_user_file_error(self, mock_exists, mock_file):
        """Test logout with file error."""
        mock_exists.return_value = True
        mock_file.side_effect = Exception("File error")

        result = logout_user("some.token")

        assert result is False


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__])
