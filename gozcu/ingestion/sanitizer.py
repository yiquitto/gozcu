"""
Input Sanitizer.

Cleans and validates raw log data before it enters the parsing pipeline.
Removes null bytes, ANSI escape codes, control characters, and detects
potential log injection patterns.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# Precompiled patterns for performance
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_LOG_INJECTION_PATTERNS = [
    re.compile(r"\r\n|\n\r|\r(?!\n)"),          # CRLF injection
    re.compile(r"\x1b\["),                        # ANSI escape start
    re.compile(r"%0[aAdD]", re.IGNORECASE),       # URL-encoded newlines
    re.compile(r"\\x0[aAdD]", re.IGNORECASE),     # Hex-encoded newlines
]


class InputSanitizer:
    """Sanitizes and validates raw log input data."""

    @staticmethod
    def sanitize(raw_input: str) -> str:
        """
        Clean raw log input by removing dangerous characters.

        Strips null bytes, ANSI escape codes, and control characters
        while preserving the meaningful log content.
        """
        if not raw_input:
            return ""

        text = raw_input

        # Remove null bytes
        text = text.replace("\x00", "")

        # Remove ANSI escape codes
        text = _ANSI_ESCAPE_RE.sub("", text)

        # Remove control characters (keep \n and \t)
        text = _CONTROL_CHARS_RE.sub("", text)

        # Strip leading/trailing whitespace
        text = text.strip()

        return text

    @staticmethod
    def validate_encoding(data: bytes) -> str:
        """
        Validate and decode bytes as UTF-8.

        Falls back to latin-1 if UTF-8 decoding fails.
        """
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            logger.warning("UTF-8 decode failed, falling back to latin-1")
            return data.decode("latin-1", errors="replace")

    @staticmethod
    def strip_ansi_codes(text: str) -> str:
        """Remove all ANSI escape sequences from text."""
        return _ANSI_ESCAPE_RE.sub("", text)

    @staticmethod
    def detect_injection(text: str) -> bool:
        """
        Detect potential log injection patterns.

        Returns True if suspicious patterns are found.
        """
        for pattern in _LOG_INJECTION_PATTERNS:
            if pattern.search(text):
                return True
        return False
