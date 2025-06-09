"""
Logging Hygiene Module

This module provides utilities to scrub sensitive data from logs to prevent
accidental exposure of passwords, API keys, tokens, and other sensitive information.
It implements configurable filters and sanitization functions.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Pattern, Union


class SensitiveDataFilter(logging.Filter):
    """
    Logging filter that removes or masks sensitive data from log records.

    This filter scans log messages and replaces sensitive patterns with
    masked versions to prevent accidental exposure in logs.
    """

    def __init__(self, patterns: Optional[List[Dict[str, Union[str, Pattern]]]] = None):
        """
        Initialize the sensitive data filter.

        Args:
            patterns: List of pattern dictionaries with 'pattern' and 'replacement' keys
        """
        super().__init__()
        self.logger = logging.getLogger(__name__)

        # Default sensitive patterns
        self.default_patterns = [
            # API Keys (OpenAI, generic)
            {
                "pattern": re.compile(r"sk-[a-zA-Z0-9]{6,}", re.IGNORECASE),
                "replacement": "[REDACTED]",
                "description": "OpenAI API Key",
            },
            {
                "pattern": re.compile(
                    r'api[_-]?key["\s]*[:=]["\s]*([a-zA-Z0-9]{6,})', re.IGNORECASE
                ),
                "replacement": r'api_key="[REDACTED]"',
                "description": "Generic API Key",
            },
            # JWT Tokens (both full JWT and partial JWT patterns)
            {
                "pattern": re.compile(
                    r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
                    re.IGNORECASE,
                ),
                "replacement": "[REDACTED]",
                "description": "Full JWT Token",
            },
            {
                "pattern": re.compile(
                    r"eyJ[a-zA-Z0-9_-]+",
                    re.IGNORECASE,
                ),
                "replacement": "[REDACTED]",
                "description": "JWT Token part",
            },
            # Bearer tokens
            {
                "pattern": re.compile(
                    r"Bearer\s+([a-zA-Z0-9_-]+)",
                    re.IGNORECASE,
                ),
                "replacement": "Bearer [REDACTED]",
                "description": "Bearer token",
            },
            # Access tokens
            {
                "pattern": re.compile(
                    r"access_token=([a-zA-Z0-9_-]+)",
                    re.IGNORECASE,
                ),
                "replacement": "access_token=[REDACTED]",
                "description": "Access token parameter",
            },
            # Passwords in various formats
            {
                "pattern": re.compile(
                    r'password["\s]*[:=]["\s]*([^\s"\']{6,})', re.IGNORECASE
                ),
                "replacement": r'password="[REDACTED]"',
                "description": "Password field",
            },
            {
                "pattern": re.compile(
                    r'passwd["\s]*[:=]["\s]*([^\s"\']{6,})', re.IGNORECASE
                ),
                "replacement": r'passwd="***REDACTED***"',
                "description": "Passwd field",
            },
            {
                "pattern": re.compile(
                    r'pwd["\s]*[:=]["\s]*([^\s"\']{6,})', re.IGNORECASE
                ),
                "replacement": r'pwd="***REDACTED***"',
                "description": "Pwd field",
            },
            # General password pattern (without quotes)
            {
                "pattern": re.compile(r"\bpassword\s+([a-zA-Z0-9]{6,})", re.IGNORECASE),
                "replacement": "password [REDACTED]",
                "description": "Password without quotes",
            },
            # Database connection strings
            {
                "pattern": re.compile(r"postgresql://[^:]+:([^@]+)@", re.IGNORECASE),
                "replacement": r"postgresql://user:***REDACTED***@",
                "description": "PostgreSQL connection string",
            },
            {
                "pattern": re.compile(r"mysql://[^:]+:([^@]+)@", re.IGNORECASE),
                "replacement": r"mysql://user:***REDACTED***@",
                "description": "MySQL connection string",
            },
            # Authorization headers
            {
                "pattern": re.compile(
                    r'authorization["\s]*[:=]["\s]*bearer\s+([a-zA-Z0-9_-]+)',
                    re.IGNORECASE,
                ),
                "replacement": r'authorization="Bearer ***REDACTED***"',
                "description": "Authorization Bearer token",
            },
            {
                "pattern": re.compile(
                    r'authorization["\s]*[:=]["\s]*([a-zA-Z0-9_-]{20,})', re.IGNORECASE
                ),
                "replacement": r'authorization="***REDACTED***"',
                "description": "Authorization token",
            },
            # Secret keys and tokens
            {
                "pattern": re.compile(
                    r'secret[_-]?key["\s]*[:=]["\s]*([a-zA-Z0-9_-]{10,})', re.IGNORECASE
                ),
                "replacement": r'secret_key="***REDACTED***"',
                "description": "Secret key",
            },
            {
                "pattern": re.compile(
                    r'access[_-]?token["\s]*[:=]["\s]*([a-zA-Z0-9_-]{10,})',
                    re.IGNORECASE,
                ),
                "replacement": r'access_token="***REDACTED***"',
                "description": "Access token",
            },
            {
                "pattern": re.compile(
                    r'refresh[_-]?token["\s]*[:=]["\s]*([a-zA-Z0-9_-]{10,})',
                    re.IGNORECASE,
                ),
                "replacement": r'refresh_token="***REDACTED***"',
                "description": "Refresh token",
            },
            # Credit card numbers (basic pattern)
            {
                "pattern": re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
                "replacement": "[REDACTED]",
                "description": "Credit card number",
            },
            # Social Security Numbers (US format)
            {
                "pattern": re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"),
                "replacement": "[REDACTED]",
                "description": "Social Security Number",
            },
            # Email addresses
            {
                "pattern": re.compile(
                    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
                ),
                "replacement": "[REDACTED]",
                "description": "Email address",
            },
            # Phone numbers (various formats) - order matters, check international first
            {
                "pattern": re.compile(r"\+1[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"),
                "replacement": "[REDACTED]",
                "description": "Phone number with country code",
            },
            {
                "pattern": re.compile(r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"),
                "replacement": "[REDACTED]",
                "description": "Phone number",
            },
        ]

        # Combine default patterns with custom patterns
        self.patterns = self.default_patterns.copy()
        if patterns:
            self.patterns.extend(patterns)

        self.logger.debug(
            f"Initialized sensitive data filter with {len(self.patterns)} patterns"
        )

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter log record to remove sensitive data.

        Args:
            record: Log record to filter

        Returns:
            bool: Always True (we modify the record but don't filter it out)
        """
        try:
            # Sanitize the main message
            if hasattr(record, "msg") and record.msg:
                record.msg = self.sanitize_text(str(record.msg))

            # Sanitize arguments if present
            if hasattr(record, "args") and record.args:
                sanitized_args = []
                for arg in record.args:
                    if isinstance(arg, str):
                        sanitized_args.append(self.sanitize_text(arg))
                    else:
                        sanitized_args.append(arg)
                record.args = tuple(sanitized_args)

            # Sanitize extra fields that might contain sensitive data
            for attr_name in ["pathname", "filename", "module", "funcName"]:
                if hasattr(record, attr_name):
                    attr_value = getattr(record, attr_name)
                    if isinstance(attr_value, str):
                        setattr(record, attr_name, self.sanitize_text(attr_value))

        except Exception as e:
            # If sanitization fails, log the error but don't break logging
            # Use a basic logger to avoid recursion
            basic_logger = logging.getLogger("logging_hygiene.error")
            basic_logger.error(f"Error in sensitive data filter: {e}")

        return True

    def sanitize_text(self, text: str) -> str:
        """
        Sanitize text by replacing sensitive patterns.

        Args:
            text: Text to sanitize

        Returns:
            str: Sanitized text with sensitive data masked
        """
        if not text:
            return text

        sanitized = text

        for pattern_info in self.patterns:
            pattern = pattern_info["pattern"]
            replacement = pattern_info["replacement"]

            try:
                if callable(replacement):
                    # Handle lambda/function replacements
                    sanitized = pattern.sub(replacement, sanitized)
                else:
                    # Handle string replacements
                    sanitized = pattern.sub(replacement, sanitized)
            except Exception as e:
                # If a specific pattern fails, continue with others
                self.logger.debug(
                    f"Pattern sanitization failed for "
                    f"{pattern_info.get('description', 'unknown')}: {e}"
                )
                continue

        return sanitized

    def add_pattern(
        self, pattern: Union[str, Pattern], replacement: str, description: str = ""
    ) -> None:
        """
        Add a custom sensitive data pattern.

        Args:
            pattern: Regex pattern to match (string or compiled pattern)
            replacement: Replacement text
            description: Description of what this pattern matches
        """
        if isinstance(pattern, str):
            pattern = re.compile(pattern, re.IGNORECASE)

        self.patterns.append(
            {"pattern": pattern, "replacement": replacement, "description": description}
        )

        self.logger.debug(f"Added custom pattern: {description}")


def setup_secure_logging(
    logger_name: Optional[str] = None,
    custom_patterns: Optional[List[Dict[str, Union[str, Pattern]]]] = None,
) -> logging.Logger:
    """
    Set up secure logging with sensitive data filtering.

    Args:
        logger_name: Name of the logger to configure (None for root logger)
        custom_patterns: Additional custom patterns to filter

    Returns:
        logging.Logger: Configured logger with sensitive data filtering
    """
    # Get or create logger
    if logger_name:
        logger = logging.getLogger(logger_name)
    else:
        logger = logging.getLogger()

    # Create and add sensitive data filter
    sensitive_filter = SensitiveDataFilter(custom_patterns)

    # Add filter to all handlers
    for handler in logger.handlers:
        handler.addFilter(sensitive_filter)

    # If no handlers exist, add a console handler with the filter
    if not logger.handlers:
        console_handler = logging.StreamHandler()
        console_handler.addFilter(sensitive_filter)

        # Set up formatter
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)8s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        console_handler.setFormatter(formatter)

        logger.addHandler(console_handler)

    logger.info("Secure logging with sensitive data filtering enabled")
    return logger


def sanitize_dict(
    data: Dict[str, Any], sensitive_keys: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Sanitize a dictionary by masking sensitive keys.

    Args:
        data: Dictionary to sanitize
        sensitive_keys: List of keys to mask (uses defaults if None)

    Returns:
        Dict[str, Any]: Sanitized dictionary
    """
    if sensitive_keys is None:
        sensitive_keys = [
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "key",
            "api_key",
            "access_token",
            "refresh_token",
            "authorization",
            "auth",
            "credential",
            "credentials",
            "private_key",
            "secret_key",
        ]

    sanitized = {}

    for key, value in data.items():
        key_lower = key.lower()

        # Check if key contains sensitive terms
        is_sensitive = any(
            sensitive_term in key_lower for sensitive_term in sensitive_keys
        )

        if is_sensitive:
            sanitized[key] = "***REDACTED***"
        elif isinstance(value, dict):
            # Recursively sanitize nested dictionaries
            sanitized[key] = sanitize_dict(value, sensitive_keys)
        elif isinstance(value, list):
            # Sanitize lists that might contain dictionaries
            sanitized_list = []
            for item in value:
                if isinstance(item, dict):
                    sanitized_list.append(sanitize_dict(item, sensitive_keys))
                else:
                    sanitized_list.append(item)
            sanitized[key] = sanitized_list
        else:
            sanitized[key] = value

    return sanitized


def create_audit_logger(name: str = "audit") -> logging.Logger:
    """
    Create a dedicated audit logger for security events.

    Args:
        name: Name of the audit logger

    Returns:
        logging.Logger: Configured audit logger
    """
    audit_logger = logging.getLogger(name)

    # Set up file handler for audit logs
    audit_handler = logging.FileHandler("audit.log")
    audit_formatter = logging.Formatter(
        "%(asctime)s [AUDIT] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    audit_handler.setFormatter(audit_formatter)

    # Add sensitive data filter
    sensitive_filter = SensitiveDataFilter()
    audit_handler.addFilter(sensitive_filter)

    audit_logger.addHandler(audit_handler)
    audit_logger.setLevel(logging.INFO)

    return audit_logger


# Global audit logger instance
audit_logger = create_audit_logger()


def log_security_event(
    event_type: str,
    user: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Log a security-related event to the audit log.

    Args:
        event_type: Type of security event (e.g., 'login', 'logout', 'auth_failure')
        user: Username associated with the event
        details: Additional details about the event
    """
    event_data = {
        "event_type": event_type,
        "user": user or "unknown",
        "timestamp": logging.Formatter().formatTime(
            logging.LogRecord(
                name="audit",
                level=logging.INFO,
                pathname="",
                lineno=0,
                msg="",
                args=(),
                exc_info=None,
            )
        ),
    }

    if details:
        # Sanitize details before logging
        event_data["details"] = sanitize_dict(details)

    audit_logger.info(f"Security Event: {event_data}")
