"""Secure logging without exposing secrets."""

from __future__ import annotations

import logging
import re
from typing import Any


class SensitiveDataFilter(logging.Filter):
    """Logging filter that redacts sensitive patterns from all LogRecords."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            if record.args:
                try:
                    record.msg = record.msg % record.args
                    record.args = ()
                except Exception:
                    pass
            record.msg = SecureLogger.redact(record.msg)
        return True


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
        (r"(sk_live_[0-9a-zA-Z]{24,})", "[REDACTED_STRIPE_KEY]"),
        (r"(xox[baprs]-[0-9a-zA-Z-]+)", "[REDACTED_SLACK_TOKEN]"),
    ]

    def __init__(self, name: str) -> None:
        """Initialize SecureLogger with a logger instance.

        Args:
            name: The name of the logger.
        """
        self._logger = logging.getLogger(name)
        # Attach filter if not already attached
        if not any(isinstance(f, SensitiveDataFilter) for f in self._logger.filters):
            self._logger.addFilter(SensitiveDataFilter())

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

    def _format_and_redact(self, message: Any, *args: Any) -> str:
        if args:
            try:
                formatted = str(message) % args
            except Exception:
                formatted = f"{message} {' '.join(str(a) for a in args)}"
        else:
            formatted = str(message)
        return self.redact(formatted)

    def debug(self, message: Any, *args: Any, **kwargs: Any) -> None:
        """Log a debug message with redaction."""
        self._logger.debug(self._format_and_redact(message, *args), **kwargs)

    def info(self, message: Any, *args: Any, **kwargs: Any) -> None:
        """Log an info message with redaction."""
        self._logger.info(self._format_and_redact(message, *args), **kwargs)

    def warning(self, message: Any, *args: Any, **kwargs: Any) -> None:
        """Log a warning message with redaction."""
        self._logger.warning(self._format_and_redact(message, *args), **kwargs)

    def error(self, message: Any, *args: Any, **kwargs: Any) -> None:
        """Log an error message with redaction."""
        self._logger.error(self._format_and_redact(message, *args), **kwargs)

    def critical(self, message: Any, *args: Any, **kwargs: Any) -> None:
        """Log a critical message with redaction."""
        self._logger.critical(self._format_and_redact(message, *args), **kwargs)
