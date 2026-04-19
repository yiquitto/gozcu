"""
Syslog Parser (RFC5424).

Parses syslog messages following the RFC5424 format:
  <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG
Also handles the simpler BSD/RFC3164 format as a fallback.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# RFC5424: <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP MSG
_RFC5424_RE = re.compile(
    r"<(?P<pri>\d{1,3})>"
    r"(?P<version>\d)?\s*"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<app_name>\S+)\s+"
    r"(?P<proc_id>\S+)\s+"
    r"(?P<msg_id>\S+)\s*"
    r"(?P<message>.*)",
    re.DOTALL,
)

# BSD/RFC3164 fallback: <PRI>TIMESTAMP HOSTNAME MSG
_RFC3164_RE = re.compile(
    r"<(?P<pri>\d{1,3})>"
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<message>.*)",
    re.DOTALL,
)


def _decode_pri(pri: int) -> tuple[int, int]:
    """Decode PRI value into facility and severity."""
    facility = pri >> 3
    severity = pri & 0x07
    return facility, severity


_SEVERITY_NAMES = {
    0: "EMERGENCY",
    1: "ALERT",
    2: "CRITICAL",
    3: "ERROR",
    4: "WARNING",
    5: "NOTICE",
    6: "INFO",
    7: "DEBUG",
}


class SyslogParser:
    """Parses RFC5424/RFC3164 syslog messages into normalized dicts."""

    @staticmethod
    def parse(raw_line: str) -> Optional[Dict[str, Any]]:
        """
        Parse a single syslog line.

        Returns a normalized dict or None if parsing fails.
        """
        if not raw_line or not raw_line.strip():
            return None

        raw_line = raw_line.strip()

        # Try RFC5424 first
        match = _RFC5424_RE.match(raw_line)
        if match:
            pri = int(match.group("pri"))
            facility, severity = _decode_pri(pri)
            return {
                "format": "RFC5424",
                "facility": facility,
                "severity": severity,
                "severity_name": _SEVERITY_NAMES.get(severity, "UNKNOWN"),
                "timestamp": match.group("timestamp"),
                "hostname": match.group("hostname"),
                "app_name": match.group("app_name"),
                "proc_id": match.group("proc_id"),
                "msg_id": match.group("msg_id"),
                "message": match.group("message").strip(),
            }

        # Fallback to RFC3164
        match = _RFC3164_RE.match(raw_line)
        if match:
            pri = int(match.group("pri"))
            facility, severity = _decode_pri(pri)
            return {
                "format": "RFC3164",
                "facility": facility,
                "severity": severity,
                "severity_name": _SEVERITY_NAMES.get(severity, "UNKNOWN"),
                "timestamp": match.group("timestamp"),
                "hostname": match.group("hostname"),
                "app_name": "-",
                "proc_id": "-",
                "msg_id": "-",
                "message": match.group("message").strip(),
            }

        # Unparseable — return raw as message
        logger.debug("Syslog line did not match RFC5424 or RFC3164 format")
        return {
            "format": "UNKNOWN",
            "facility": -1,
            "severity": -1,
            "severity_name": "UNKNOWN",
            "timestamp": "",
            "hostname": "",
            "app_name": "-",
            "proc_id": "-",
            "msg_id": "-",
            "message": raw_line,
        }
