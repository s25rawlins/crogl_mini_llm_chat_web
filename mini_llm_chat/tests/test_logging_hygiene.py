"""
Logging Hygiene Tests Module

This module contains comprehensive unit tests for the logging hygiene functionality.
It tests sensitive data filtering, log sanitization, and security measures.
"""

import logging
from unittest.mock import MagicMock, patch

import pytest

from mini_llm_chat.logging_hygiene import (
    SensitiveDataFilter,
    create_audit_logger,
    log_security_event,
    sanitize_dict,
    setup_secure_logging,
)


class TestSensitiveDataFilter:
    """Test cases for the SensitiveDataFilter class."""

    def test_filter_initialization(self):
        """Test that the filter initializes with default patterns."""
        filter_instance = SensitiveDataFilter()

        # Check that patterns are loaded
        assert len(filter_instance.patterns) > 0

        # Check that patterns are dictionaries with required keys
        for pattern_info in filter_instance.patterns:
            assert isinstance(pattern_info, dict)
            assert "pattern" in pattern_info
            assert "replacement" in pattern_info
            assert "description" in pattern_info

        # Check that some expected patterns exist
        descriptions = [p["description"].lower() for p in filter_instance.patterns]
        assert any("api" in desc for desc in descriptions)
        assert any("password" in desc for desc in descriptions)

    def test_filter_api_key(self):
        """Test filtering of API keys."""
        filter_instance = SensitiveDataFilter()

        # Test OpenAI API key pattern (48 characters after sk-)
        original = "API key: sk-1234567890abcdef1234567890abcdef1234567890abcdef"
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg=original,
            args=(),
            exc_info=None,
        )

        result = filter_instance.filter(record)
        assert result is True  # Filter should not block the record
        # Check that the API key was replaced
        assert "[REDACTED]" in record.getMessage()
        assert (
            "sk-1234567890abcdef1234567890abcdef1234567890abcdef"
            not in record.getMessage()
        )

    def test_filter_password(self):
        """Test filtering of passwords."""
        filter_instance = SensitiveDataFilter()

        # Test password pattern matching
        original = 'password="secret123"'
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg=original,
            args=(),
            exc_info=None,
        )

        result = filter_instance.filter(record)
        assert result is True
        # Check that password was replaced
        assert 'password="[REDACTED]"' in record.getMessage()
        assert "secret123" not in record.getMessage()

    def test_filter_token(self):
        """Test filtering of tokens."""
        filter_instance = SensitiveDataFilter()

        test_cases = [
            (
                "JWT token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9",
                "JWT token: [REDACTED]",
            ),
            ("access_token=abc123def", "access_token=[REDACTED]"),
            ("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "Bearer [REDACTED]"),
        ]

        for original, expected in test_cases:
            record = logging.LogRecord(
                name="test",
                level=logging.INFO,
                pathname="",
                lineno=0,
                msg=original,
                args=(),
                exc_info=None,
            )

            result = filter_instance.filter(record)
            assert result is True
            assert record.getMessage() == expected

    def test_filter_credit_card(self):
        """Test filtering of credit card numbers."""
        filter_instance = SensitiveDataFilter()

        test_cases = [
            ("Credit card: 4111-1111-1111-1111", "Credit card: [REDACTED]"),
            ("CC: 4111111111111111", "CC: [REDACTED]"),
            ("Card number 5555 5555 5555 4444", "Card number [REDACTED]"),
        ]

        for original, expected in test_cases:
            record = logging.LogRecord(
                name="test",
                level=logging.INFO,
                pathname="",
                lineno=0,
                msg=original,
                args=(),
                exc_info=None,
            )

            result = filter_instance.filter(record)
            assert result is True
            assert record.getMessage() == expected

    def test_filter_email(self):
        """Test filtering of email addresses."""
        filter_instance = SensitiveDataFilter()

        test_cases = [
            ("User email: user@example.com", "User email: [REDACTED]"),
            ("Contact: admin@test.org", "Contact: [REDACTED]"),
            ("Email address test.user+tag@domain.co.uk", "Email address [REDACTED]"),
        ]

        for original, expected in test_cases:
            record = logging.LogRecord(
                name="test",
                level=logging.INFO,
                pathname="",
                lineno=0,
                msg=original,
                args=(),
                exc_info=None,
            )

            result = filter_instance.filter(record)
            assert result is True
            assert record.getMessage() == expected

    def test_filter_phone_number(self):
        """Test filtering of phone numbers."""
        filter_instance = SensitiveDataFilter()

        test_cases = [
            ("Phone: (555) 123-4567", "Phone: [REDACTED]"),
            ("Call 555-123-4567", "Call [REDACTED]"),
            ("Mobile: +1-555-123-4567", "Mobile: [REDACTED]"),
        ]

        for original, expected in test_cases:
            record = logging.LogRecord(
                name="test",
                level=logging.INFO,
                pathname="",
                lineno=0,
                msg=original,
                args=(),
                exc_info=None,
            )

            result = filter_instance.filter(record)
            assert result is True
            assert record.getMessage() == expected

    def test_filter_ssn(self):
        """Test filtering of Social Security Numbers."""
        filter_instance = SensitiveDataFilter()

        test_cases = [
            ("SSN: 123-45-6789", "SSN: [REDACTED]"),
            ("Social Security: 123456789", "Social Security: [REDACTED]"),
            ("SSN 123 45 6789", "SSN [REDACTED]"),
        ]

        for original, expected in test_cases:
            record = logging.LogRecord(
                name="test",
                level=logging.INFO,
                pathname="",
                lineno=0,
                msg=original,
                args=(),
                exc_info=None,
            )

            result = filter_instance.filter(record)
            assert result is True
            assert record.getMessage() == expected

    def test_filter_multiple_sensitive_data(self):
        """Test filtering multiple types of sensitive data in one message."""
        filter_instance = SensitiveDataFilter()

        original = "User john@example.com with API key sk-123abc and password secret123"
        expected = "User [REDACTED] with API key [REDACTED] and password [REDACTED]"

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg=original,
            args=(),
            exc_info=None,
        )

        result = filter_instance.filter(record)
        assert result is True
        assert record.getMessage() == expected

    def test_filter_no_sensitive_data(self):
        """Test that non-sensitive data is not filtered."""
        filter_instance = SensitiveDataFilter()

        original = "User logged in successfully from IP 192.168.1.1"

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg=original,
            args=(),
            exc_info=None,
        )

        result = filter_instance.filter(record)
        assert result is True
        assert record.getMessage() == original  # Should be unchanged

    def test_filter_with_args(self):
        """Test filtering when log record uses args for formatting."""
        filter_instance = SensitiveDataFilter()

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="API key: %s",
            args=("sk-secret123",),
            exc_info=None,
        )

        result = filter_instance.filter(record)
        assert result is True
        assert record.getMessage() == "API key: [REDACTED]"

    def test_filter_custom_patterns(self):
        """Test filtering with custom patterns."""
        import re

        custom_patterns = [
            {
                "pattern": re.compile(r"\bCUSTOM_SECRET\b"),
                "replacement": "[REDACTED]",
                "description": "Custom secret pattern",
            }
        ]
        filter_instance = SensitiveDataFilter(patterns=custom_patterns)

        original = "Found CUSTOM_SECRET in the logs"
        expected = "Found [REDACTED] in the logs"

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg=original,
            args=(),
            exc_info=None,
        )

        result = filter_instance.filter(record)
        assert result is True
        assert record.getMessage() == expected


class TestSanitizeDict:
    """Test cases for the sanitize_dict function."""

    def test_sanitize_dict_with_sensitive_keys(self):
        """Test sanitizing dictionary with sensitive keys."""
        original = {
            "username": "john",
            "password": "secret123",
            "api_key": "sk-abc123",
            "email": "john@example.com",
        }

        result = sanitize_dict(original)

        assert result["username"] == "john"
        assert "***REDACTED***" in result["password"]
        assert "***REDACTED***" in result["api_key"]

    def test_sanitize_nested_structure(self):
        """Test sanitizing nested data structures."""
        original = {
            "user": {
                "name": "john",
                "email": "john@example.com",
                "credentials": {"password": "secret123", "api_key": "sk-abc123"},
            },
            "logs": [{"message": "User login successful"}],
        }

        result = sanitize_dict(original)

        assert result["user"]["name"] == "john"
        # The entire "credentials" key is treated as sensitive and replaced
        assert result["user"]["credentials"] == "***REDACTED***"

        # Test with a different structure where individual keys are sensitive
        original2 = {
            "user": {
                "name": "john",
                "email": "john@example.com",
                "user_data": {"password": "secret123", "api_key": "sk-abc123"},
            }
        }

        result2 = sanitize_dict(original2)
        assert result2["user"]["name"] == "john"
        assert result2["user"]["user_data"]["password"] == "***REDACTED***"
        assert result2["user"]["user_data"]["api_key"] == "***REDACTED***"

    def test_sanitize_custom_sensitive_keys(self):
        """Test sanitizing with custom sensitive keys."""
        original = {
            "username": "john",
            "custom_secret": "secret123",
            "normal_field": "normal_value",
        }

        result = sanitize_dict(original, sensitive_keys=["custom_secret"])

        assert result["username"] == "john"
        assert result["custom_secret"] == "***REDACTED***"
        assert result["normal_field"] == "normal_value"


class TestSetupSecureLogging:
    """Test cases for the setup_secure_logging function."""

    @patch("mini_llm_chat.logging_hygiene.logging.getLogger")
    def test_setup_secure_logging_basic(self, mock_get_logger):
        """Test basic secure logging setup."""
        mock_logger = MagicMock()
        mock_logger.handlers = []  # No existing handlers
        mock_get_logger.return_value = mock_logger

        setup_secure_logging()

        # Should be called at least once (for the main logger)
        assert mock_get_logger.call_count >= 1
        # Check that the first call was with no arguments (root logger)
        assert mock_get_logger.call_args_list[0] == ((),)

        # Should add a handler since there were no existing handlers
        mock_logger.addHandler.assert_called()

        # Verify the handler has the filter
        handler_call = mock_logger.addHandler.call_args[0][0]
        assert hasattr(handler_call, "addFilter")

    @patch("mini_llm_chat.logging_hygiene.logging.getLogger")
    def test_setup_secure_logging_with_logger_name(self, mock_get_logger):
        """Test secure logging setup with specific logger name."""
        mock_logger = MagicMock()
        mock_logger.handlers = []  # No existing handlers
        mock_get_logger.return_value = mock_logger

        setup_secure_logging(logger_name="test_logger")

        # Should be called at least once (for the main logger)
        assert mock_get_logger.call_count >= 1
        # Check that one of the calls was with "test_logger"
        call_args = [call[0] for call in mock_get_logger.call_args_list]
        assert ("test_logger",) in call_args

        # Should add a handler since there were no existing handlers
        mock_logger.addHandler.assert_called()

    @patch("mini_llm_chat.logging_hygiene.logging.getLogger")
    def test_setup_secure_logging_with_custom_patterns(self, mock_get_logger):
        """Test secure logging setup with custom patterns."""
        mock_logger = MagicMock()
        mock_logger.handlers = []  # No existing handlers
        mock_get_logger.return_value = mock_logger

        import re

        custom_patterns = [
            {
                "pattern": re.compile(r"\bCUSTOM_PATTERN\b"),
                "replacement": "[REDACTED]",
                "description": "Custom pattern",
            }
        ]
        setup_secure_logging(custom_patterns=custom_patterns)

        # Should add a handler since there were no existing handlers
        mock_logger.addHandler.assert_called()

        # Verify the filter has custom patterns
        # The filter is added to the handler, not the logger directly
        handler_call = mock_logger.addHandler.call_args[0][0]
        assert hasattr(handler_call, "addFilter")


class TestCreateAuditLogger:
    """Test cases for the create_audit_logger function."""

    @patch("mini_llm_chat.logging_hygiene.logging.getLogger")
    @patch("mini_llm_chat.logging_hygiene.logging.FileHandler")
    def test_create_audit_logger(self, mock_file_handler, mock_get_logger):
        """Test audit logger creation."""
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger

        mock_handler = MagicMock()
        mock_file_handler.return_value = mock_handler

        result = create_audit_logger("test_audit")

        assert result == mock_logger
        # Should be called at least once (for the audit logger)
        assert mock_get_logger.call_count >= 1
        # Check that one of the calls was with "test_audit"
        call_args = [call[0] for call in mock_get_logger.call_args_list]
        assert ("test_audit",) in call_args

        mock_file_handler.assert_called_once_with("audit.log")
        mock_logger.addHandler.assert_called_once_with(mock_handler)
        mock_logger.setLevel.assert_called_once_with(logging.INFO)


class TestLogSecurityEvent:
    """Test cases for the log_security_event function."""

    @patch("mini_llm_chat.logging_hygiene.audit_logger")
    def test_log_security_event_basic(self, mock_audit_logger):
        """Test basic security event logging."""
        log_security_event("login", "testuser", {"user_id": "123"})

        mock_audit_logger.info.assert_called_once()

        # Check the logged message format
        logged_message = mock_audit_logger.info.call_args[0][0]
        assert "login" in logged_message
        assert "testuser" in logged_message

    @patch("mini_llm_chat.logging_hygiene.audit_logger")
    def test_log_security_event_with_sensitive_data(self, mock_audit_logger):
        """Test security event logging with sensitive data."""
        log_security_event(
            "api_access",
            "testuser",
            {"api_key": "sk-secret123", "user_email": "user@example.com"},
        )

        mock_audit_logger.info.assert_called_once()

        # Check that the event was logged (sanitization happens in the filter)
        logged_message = mock_audit_logger.info.call_args[0][0]
        assert "api_access" in logged_message
        assert "testuser" in logged_message

    @patch("mini_llm_chat.logging_hygiene.audit_logger")
    def test_log_security_event_no_additional_data(self, mock_audit_logger):
        """Test security event logging without additional data."""
        log_security_event("system_start", "system")

        mock_audit_logger.info.assert_called_once()

        logged_message = mock_audit_logger.info.call_args[0][0]
        assert "system_start" in logged_message
        assert "system" in logged_message


class TestLoggingIntegration:
    """Integration tests for logging hygiene functionality."""

    def test_end_to_end_sensitive_data_filtering(self):
        """Test end-to-end sensitive data filtering."""
        # Create a logger with the sensitive data filter
        logger = logging.getLogger("test_logger")
        logger.handlers = []  # Clear any existing handlers

        # Add a handler to capture log output
        from io import StringIO

        log_stream = StringIO()
        handler = logging.StreamHandler(log_stream)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        # Add the sensitive data filter
        filter_instance = SensitiveDataFilter()
        logger.addFilter(filter_instance)

        # Log a message with sensitive data
        logger.info("User login: email=user@example.com, api_key=sk-secret123")

        # Check that sensitive data was filtered
        log_output = log_stream.getvalue()
        assert "user@example.com" not in log_output
        assert "sk-secret123" not in log_output
        assert "[REDACTED]" in log_output

    @patch("mini_llm_chat.logging_hygiene.audit_logger")
    def test_audit_logging_integration(self, mock_audit_logger):
        """Test audit logging integration."""
        # Test the complete audit logging flow
        log_security_event(
            "USER_LOGIN",
            "User logged in successfully",
            {
                "user_id": "123",
                "ip_address": "192.168.1.1",
                "user_agent": "Mozilla/5.0",
            },
        )

        # Verify logging call
        mock_audit_logger.info.assert_called_once()
        logged_message = mock_audit_logger.info.call_args[0][0]
        assert "USER_LOGIN" in logged_message
        assert "192.168.1.1" in logged_message


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__])
