"""Secure logging without exposing secrets."""

from __future__ import annotations

import logging
import re
from typing import Any


class SecureLogger:
    """Logger wrapper that redacts sensitive information from all output."""

    SECRET_PATTERNS = [
        (r"(ghp_[a-zA-Z0-9_]{36})", "[REDACTED_PAT]"),
        (r"(ghu_[a-zA-Z0-9_]{36})", "[REDACTED_USER_TOKEN]"),
        (r"(github_pat_[a-zA-Z0-9_]+)", "[REDACTED_PAT]"),
        (r"(AKIA[0-9A-Z]{16})", "[REDACTED_AWS_KEY]"),
        (r"(aws_secret_access_key.*?=.*?\S+)", "[REDACTED_AWS_SECRET]"),
        (r"(authorization\s*:\s*bearer\s+\S+)", "[REDACTED_AUTH_HEADER]"),
        (r"(password\s*[:=]\s*\S+)", "[REDACTED_PASSWORD]"),
        (r"(api[_-]?key\s*[:=]\s*\S+)", "[REDACTED_API_KEY]"),
        (r"(token\s*[:=]\s*\S+)", "[REDACTED_TOKEN]"),
    ]

    def __init__(self, name: str) -> None:
        """Initialize SecureLogger with a logger instance.

        Args:
            name: The name of the logger.
        """
        self._logger = logging.getLogger(name)

    @staticmethod
    def redact(message: Any) -> str:
        """Redact secrets from a message.

        Args:
            message: The message to redact.

        Returns:
            The message with secrets redacted.
        """
        text = str(message)
        for pattern, replacement in SecureLogger.SECRET_PATTERNS:
            text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        return text

    def debug(self, message: Any, *args: Any, **kwargs: Any) -> None:
        """Log a debug message with redaction."""
        self._logger.debug(self.redact(message), *args, **kwargs)

    def info(self, message: Any, *args: Any, **kwargs: Any) -> None:
        """Log an info message with redaction."""
        self._logger.info(self.redact(message), *args, **kwargs)

    def warning(self, message: Any, *args: Any, **kwargs: Any) -> None:
        """Log a warning message with redaction."""
        self._logger.warning(self.redact(message), *args, **kwargs)

    def error(self, message: Any, *args: Any, **kwargs: Any) -> None:
        """Log an error message with redaction."""
        self._logger.error(self.redact(message), *args, **kwargs)

    def critical(self, message: Any, *args: Any, **kwargs: Any) -> None:
        """Log a critical message with redaction."""
        self._logger.critical(self.redact(message), *args, **kwargs)
