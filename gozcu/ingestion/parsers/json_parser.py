"""
JSON Web Log Parser.

Parses JSON-formatted web server access logs (e.g., from Nginx or Apache
configured with JSON output). Extracts HTTP method, path, status code,
user agent, and source IP into a normalized dictionary.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Common field name aliases across different log formats
_FIELD_ALIASES = {
    "method": ["method", "http_method", "request_method", "verb"],
    "path": ["path", "uri", "url", "request_uri", "request_path", "request"],
    "status_code": ["status", "status_code", "http_status", "response_code"],
    "user_agent": ["user_agent", "http_user_agent", "useragent", "ua"],
    "source_ip": ["remote_addr", "client_ip", "source_ip", "ip", "clientip", "src_ip"],
    "timestamp": ["timestamp", "time", "@timestamp", "date", "datetime"],
    "response_size": ["body_bytes_sent", "bytes", "response_size", "size"],
    "referer": ["referer", "http_referer", "referrer"],
}


class JsonWebLogParser:
    """Parses JSON-formatted web access log entries."""

    @staticmethod
    def parse(raw_json: str) -> Optional[Dict[str, Any]]:
        """
        Parse a JSON web log entry.

        Returns a normalized dict or None if parsing fails.
        """
        if not raw_json or not raw_json.strip():
            return None

        try:
            data = json.loads(raw_json.strip())
        except json.JSONDecodeError as e:
            logger.debug(f"JSON parse failed: {e}")
            return None

        if not isinstance(data, dict):
            logger.debug("JSON root is not an object")
            return None

        return JsonWebLogParser._normalize(data)

    @staticmethod
    def _normalize(data: Dict[str, Any]) -> Dict[str, Any]:
        """Map various field names to a standard schema."""
        result: Dict[str, Any] = {
            "format": "JSON_WEB_LOG",
            "method": "",
            "path": "",
            "status_code": 0,
            "user_agent": "",
            "source_ip": "",
            "timestamp": "",
            "response_size": 0,
            "referer": "",
            "message": "",
        }

        # Resolve aliases
        for canonical, aliases in _FIELD_ALIASES.items():
            for alias in aliases:
                if alias in data:
                    value = data[alias]
                    # Convert status_code and response_size to int
                    if canonical in ("status_code", "response_size"):
                        try:
                            value = int(value)
                        except (ValueError, TypeError):
                            value = 0
                    result[canonical] = value
                    break

        # If 'request' field contains "GET /path HTTP/1.1", split it
        if not result["method"] and not result["path"]:
            request_str = data.get("request", "")
            if isinstance(request_str, str) and " " in request_str:
                parts = request_str.split(" ", 2)
                if len(parts) >= 2:
                    result["method"] = parts[0]
                    result["path"] = parts[1]

        # Build a summary message
        result["message"] = (
            f"{result['method']} {result['path']} "
            f"-> {result['status_code']} "
            f"from {result['source_ip']}"
        )

        return result
