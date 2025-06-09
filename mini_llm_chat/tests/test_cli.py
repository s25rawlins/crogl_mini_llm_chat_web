"""
CLI Tests Module

This module contains unit tests for the command-line interface functionality.
It tests argument parsing, validation, and basic CLI behavior using subprocess
to simulate real command-line usage.

The tests ensure that the CLI behaves correctly with various argument combinations
and provides appropriate error messages for invalid configurations.
"""

import os
import subprocess
import sys
from unittest.mock import patch

import pytest

# Import the modules we want to test
from mini_llm_chat.cli import (
    create_argument_parser,
    main,
    setup_logging,
    validate_arguments,
)


class TestArgumentParser:
    """Test cases for the argument parser functionality."""

    def test_parser_creation(self):
        """Test that the argument parser is created correctly."""
        parser = create_argument_parser()

        # Check that parser is created
        assert parser is not None
        assert parser.prog == "mini-llm-chat"

        # Check that required arguments are present
        help_text = parser.format_help()
        assert "--api-key" in help_text
        assert "--max-calls" in help_text
        assert "--time-window" in help_text
        assert "--log-level" in help_text

    def test_default_values(self):
        """Test that default values are set correctly."""
        # Clear environment variables that might affect defaults
        env_vars_to_clear = [
            "OPENAI_API_KEY",
            "RATE_LIMIT_MAX_CALLS",
            "RATE_LIMIT_TIME_WINDOW",
            "LOG_LEVEL",
            "DB_BACKEND",
            "DATABASE_URL",
        ]

        # Remove environment variables if they exist
        for var in env_vars_to_clear:
            if var in os.environ:
                del os.environ[var]

        try:
            parser = create_argument_parser()
            args = parser.parse_args([])

            assert args.api_key is None  # No default API key
            assert args.max_calls == 3  # Default max calls
            assert args.time_window == 60  # Default time window
            assert args.log_level == "INFO"  # Default log level
        finally:
            # Restore any environment variables that were cleared
            pass

    def test_environment_variable_defaults(self):
        """Test that environment variables are used as defaults."""
        # Set environment variables
        env_vars = {
            "OPENAI_API_KEY": "sk-test-key-123",
            "RATE_LIMIT_MAX_CALLS": "5",
            "RATE_LIMIT_TIME_WINDOW": "120",
            "LOG_LEVEL": "DEBUG",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            # Create parser inside the patched environment so os.getenv() reads the test values
            parser = create_argument_parser()
            args = parser.parse_args([])

            assert args.api_key == "sk-test-key-123"
            assert args.max_calls == 5
            assert args.time_window == 120
            assert args.log_level == "DEBUG"

    def test_command_line_overrides_environment(self):
        """Test that command-line arguments override environment variables."""
        parser = create_argument_parser()

        # Set environment variables
        env_vars = {
            "OPENAI_API_KEY": "sk-env-key",
            "RATE_LIMIT_MAX_CALLS": "5",
        }

        with patch.dict(os.environ, env_vars):
            args = parser.parse_args(["--api-key", "sk-cli-key", "--max-calls", "10"])

            assert args.api_key == "sk-cli-key"  # CLI overrides env
            assert args.max_calls == 10  # CLI overrides env


class TestArgumentValidation:
    """Test cases for argument validation functionality."""

    def test_valid_arguments(self):
        """Test validation with valid arguments."""
        parser = create_argument_parser()
        args = parser.parse_args(
            [
                "--api-key",
                "sk-test-key-1234567890123456789012345678901234567890",
                "--max-calls",
                "5",
                "--time-window",
                "60",
            ]
        )

        # Mock the logger to avoid setup issues
        with patch("mini_llm_chat.cli.logging.getLogger"):
            result = validate_arguments(args)
            assert result is True

    def test_missing_api_key(self):
        """Test validation fails when API key is missing."""
        # Clear environment variables that might contain API key
        env_vars_to_clear = ["OPENAI_API_KEY"]

        # Remove environment variables if they exist
        original_values = {}
        for var in env_vars_to_clear:
            if var in os.environ:
                original_values[var] = os.environ[var]
                del os.environ[var]

        try:
            parser = create_argument_parser()
            args = parser.parse_args([])  # No API key provided

            with patch("mini_llm_chat.cli.logging.getLogger"):
                with patch("builtins.print") as mock_print:
                    result = validate_arguments(args)
                    assert result is False
                    # Check that error message was printed
                    mock_print.assert_called()
                    error_calls = [
                        call
                        for call in mock_print.call_args_list
                        if "API key is required" in str(call)
                    ]
                    assert len(error_calls) > 0
        finally:
            # Restore original environment variables
            for var, value in original_values.items():
                os.environ[var] = value

    def test_invalid_api_key_format(self):
        """Test validation fails with invalid API key format."""
        parser = create_argument_parser()
        args = parser.parse_args(["--api-key", "invalid-key"])

        with patch("mini_llm_chat.cli.logging.getLogger"):
            with patch("builtins.print") as mock_print:
                result = validate_arguments(args)
                assert result is False
                # Check that error message was printed
                mock_print.assert_called()

    def test_invalid_max_calls(self):
        """Test validation fails with invalid max_calls values."""
        parser = create_argument_parser()

        # Test negative value
        args = parser.parse_args(
            [
                "--api-key",
                "sk-test-key-1234567890123456789012345678901234567890",
                "--max-calls",
                "-1",
            ]
        )

        with patch("mini_llm_chat.cli.logging.getLogger"):
            with patch("builtins.print") as mock_print:
                result = validate_arguments(args)
                assert result is False
                mock_print.assert_called()

    def test_invalid_time_window(self):
        """Test validation fails with invalid time_window values."""
        parser = create_argument_parser()

        # Test zero value
        args = parser.parse_args(
            [
                "--api-key",
                "sk-test-key-1234567890123456789012345678901234567890",
                "--time-window",
                "0",
            ]
        )

        with patch("mini_llm_chat.cli.logging.getLogger"):
            with patch("builtins.print") as mock_print:
                result = validate_arguments(args)
                assert result is False
                mock_print.assert_called()

    def test_high_rate_warning(self):
        """Test that warnings are shown for high API call rates."""
        parser = create_argument_parser()
        args = parser.parse_args(
            [
                "--api-key",
                "sk-test-key-1234567890123456789012345678901234567890",
                "--max-calls",
                "100",  # Very high
                "--time-window",
                "60",
            ]
        )

        with patch("mini_llm_chat.cli.logging.getLogger"):
            with patch("builtins.print") as mock_print:
                result = validate_arguments(args)
                assert result is True  # Still valid, just warning
                # Check that warning was printed
                warning_calls = [
                    call for call in mock_print.call_args_list if "Warning" in str(call)
                ]
                assert len(warning_calls) > 0


class TestLoggingSetup:
    """Test cases for logging configuration."""

    def test_setup_logging_info_level(self):
        """Test logging setup with INFO level."""
        with patch("logging.basicConfig") as mock_config:
            setup_logging("INFO")
            mock_config.assert_called_once()

            # Check that INFO level was used
            call_args = mock_config.call_args
            assert call_args[1]["level"] == 20  # logging.INFO = 20

    def test_setup_logging_debug_level(self):
        """Test logging setup with DEBUG level."""
        with patch("logging.basicConfig") as mock_config:
            setup_logging("DEBUG")
            mock_config.assert_called_once()

            # Check that DEBUG level was used
            call_args = mock_config.call_args
            assert call_args[1]["level"] == 10  # logging.DEBUG = 10

    def test_setup_logging_invalid_level(self):
        """Test logging setup with invalid level raises error."""
        with pytest.raises(ValueError):
            setup_logging("INVALID")


class TestCLIIntegration:
    """Integration tests for the CLI using subprocess."""

    def test_help_command(self):
        """Test that --help command works and shows expected content."""
        result = subprocess.run(
            [sys.executable, "-m", "mini_llm_chat", "--help"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "usage:" in result.stdout.lower()
        assert "--api-key" in result.stdout
        assert "--max-calls" in result.stdout
        assert "--time-window" in result.stdout
        assert "--log-level" in result.stdout

    def test_version_command(self):
        """Test that --version command works."""
        result = subprocess.run(
            [sys.executable, "-m", "mini_llm_chat", "--version"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "0.1.0" in result.stdout

    def test_missing_api_key_error(self):
        """Test that missing API key results in error exit code."""
        # Clear environment variables that might contain API key
        env = os.environ.copy()
        env.pop("OPENAI_API_KEY", None)

        # Also clear any other environment variables that might be loaded from .env
        env.pop("DATABASE_URL", None)
        env.pop("JWT_SECRET_KEY", None)
        env.pop("RATE_LIMIT_MAX_CALLS", None)
        env.pop("RATE_LIMIT_TIME_WINDOW", None)
        env.pop("LOG_LEVEL", None)
        env.pop("MINI_LLM_CHAT_TOKEN", None)

        # Create a test script that prevents .env loading
        import tempfile

        test_script = """
import sys
import os
from unittest.mock import patch

# Mock load_dotenv to prevent loading .env file
with patch('mini_llm_chat.cli.load_dotenv'):
    from mini_llm_chat.cli import main
    main()
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(test_script)
            f.flush()

            try:
                result = subprocess.run(
                    [sys.executable, f.name],
                    capture_output=True,
                    text=True,
                    env=env,
                )
            finally:
                os.unlink(f.name)

        assert result.returncode == 1  # Configuration error
        assert (
            "API key is required" in result.stdout
            or "API key is required" in result.stderr
        )

    def test_invalid_log_level_error(self):
        """Test that invalid log level is rejected."""
        result = subprocess.run(
            [sys.executable, "-m", "mini_llm_chat", "--log-level", "INVALID"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 2  # argparse error
        assert "invalid choice" in result.stderr.lower()


class TestMainFunction:
    """Test cases for the main() function."""

    @patch("mini_llm_chat.cli.run_chat_repl")
    @patch("mini_llm_chat.cli.validate_arguments")
    @patch("mini_llm_chat.cli.setup_logging")
    def test_main_success_flow(self, mock_setup_logging, mock_validate, mock_run_chat):
        """Test successful execution flow of main()."""
        # Mock successful validation
        mock_validate.return_value = True

        # Mock sys.argv to provide test arguments
        test_args = [
            "mini-llm-chat",
            "--api-key",
            "sk-test-key-1234567890123456789012345678901234567890",
            "--max-calls",
            "5",
        ]

        with patch.object(sys, "argv", test_args):
            with patch("builtins.print"):  # Suppress output
                main()

        # Verify that all expected functions were called
        mock_setup_logging.assert_called_once()
        mock_validate.assert_called_once()
        mock_run_chat.assert_called_once()

    @patch("mini_llm_chat.cli.validate_arguments")
    @patch("mini_llm_chat.cli.setup_logging")
    def test_main_validation_failure(self, mock_setup_logging, mock_validate):
        """Test main() exits with code 1 when validation fails."""
        # Mock failed validation
        mock_validate.return_value = False

        test_args = ["mini-llm-chat"]

        with patch.object(sys, "argv", test_args):
            with patch("builtins.print"):  # Suppress output
                with pytest.raises(SystemExit) as exc_info:
                    main()

                assert exc_info.value.code == 1

    @patch("mini_llm_chat.cli.run_chat_repl")
    @patch("mini_llm_chat.cli.validate_arguments")
    @patch("mini_llm_chat.cli.setup_logging")
    def test_main_keyboard_interrupt(
        self, mock_setup_logging, mock_validate, mock_run_chat
    ):
        """Test main() handles KeyboardInterrupt gracefully."""
        mock_validate.return_value = True
        mock_run_chat.side_effect = KeyboardInterrupt()

        test_args = [
            "mini-llm-chat",
            "--api-key",
            "sk-test-key-1234567890123456789012345678901234567890",
        ]

        with patch.object(sys, "argv", test_args):
            with patch("builtins.print"):  # Suppress output
                with pytest.raises(SystemExit) as exc_info:
                    main()

                assert exc_info.value.code == 0  # Graceful exit

    @patch("mini_llm_chat.cli.run_chat_repl")
    @patch("mini_llm_chat.cli.validate_arguments")
    @patch("mini_llm_chat.cli.setup_logging")
    def test_main_unexpected_exception(
        self, mock_setup_logging, mock_validate, mock_run_chat
    ):
        """Test main() handles unexpected exceptions."""
        mock_validate.return_value = True
        mock_run_chat.side_effect = Exception("Unexpected error")

        test_args = [
            "mini-llm-chat",
            "--api-key",
            "sk-test-key-1234567890123456789012345678901234567890",
        ]

        with patch.object(sys, "argv", test_args):
            with patch("builtins.print"):  # Suppress output
                with pytest.raises(SystemExit) as exc_info:
                    main()

                assert exc_info.value.code == 2  # Runtime error


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__])
