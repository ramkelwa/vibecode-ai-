"""Structured logging with automatic redaction of sensitive values.

The scanner and API never log passwords, API keys, session tokens or
authorization headers. A redaction filter scrubs known-sensitive keys and
common secret patterns from every record before it is emitted.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Any, Dict, Iterable

from app.core.config import settings

_REDACTED = "***REDACTED***"

# Keys whose values must never be logged.
_SENSITIVE_KEYS = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "secret_key",
    "api_key",
    "apikey",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "auth",
    "cookie",
    "set-cookie",
    "session",
    "session_id",
    "jwt",
    "private_key",
    "client_secret",
    "x-api-key",
    "proxy-authorization",
}

# Patterns that look like secrets even inside free-form text.
_SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization\s*[:=]\s*)(bearer\s+)?[a-z0-9._\-]+"),
    re.compile(r"(?i)(api[_-]?key\s*[:=]\s*)[a-z0-9._\-]+"),
    re.compile(r"(?i)(password\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(token\s*[:=]\s*)[a-z0-9._\-]+"),
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"),  # JWT
]


class RedactionFilter(logging.Filter):
    """Scrubs sensitive keys and secret-looking substrings from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.redact_text(record.msg)
        if record.args:
            record.args = tuple(
                self.redact_text(a) if isinstance(a, str) else a for a in self._as_tuple(record.args)
            )
        return True

    @staticmethod
    def _as_tuple(args: Any) -> Iterable[Any]:
        return args if isinstance(args, tuple) else (args,)

    @staticmethod
    def redact_text(text: str) -> str:
        for pattern in _SECRET_PATTERNS:
            text = pattern.sub(lambda m: m.group(1) + _REDACTED, text)
        return text


def redact_mapping(data: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of a mapping with sensitive values replaced."""
    safe: Dict[str, Any] = {}
    for key, value in data.items():
        if str(key).lower() in _SENSITIVE_KEYS:
            safe[key] = _REDACTED
        elif isinstance(value, dict):
            safe[key] = redact_mapping(value)
        else:
            safe[key] = value
    return safe


def _build_logger() -> logging.Logger:
    logger = logging.getLogger("vibeshield")
    logger.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        fmt = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
        handler.setFormatter(logging.Formatter(fmt))
        handler.addFilter(RedactionFilter())
        logger.addHandler(handler)

    return logger


logger = _build_logger()


def get_logger(name: str | None = None) -> logging.Logger:
    return logger if not name else logger.getChild(name)
