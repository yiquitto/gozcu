"""
GÖZCÜ Enumerations.

Central definition of all enum types used across the application.
These enums enforce strict typing for log sources, threat categories,
decision states, and mitigation action types.
"""

from enum import Enum


class SourceType(str, Enum):
    """Type of log source that produced the telemetry event."""

    SYSLOG = "SYSLOG"
    WINDOWS_EVENT = "WINDOWS_EVENT"
    WEB_LOG = "WEB_LOG"


class ThreatCategory(str, Enum):
    """AI-assigned threat classification category."""

    RECONNAISSANCE = "RECONNAISSANCE"
    SQLI = "SQLI"
    BRUTE_FORCE = "BRUTE_FORCE"
    XSS = "XSS"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    MALWARE = "MALWARE"
    BENIGN = "BENIGN"


class DecisionState(str, Enum):
    """State of a decision within the 30-second countdown state machine."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    AUTONOMOUS = "AUTONOMOUS"
    EXPIRED = "EXPIRED"


class ActionType(str, Enum):
    """Type of mitigation action the system can execute."""

    NULL_ROUTE = "NULL_ROUTE"
    BLOCK_IP = "BLOCK_IP"
    RESTART_SERVICE = "RESTART_SERVICE"
    QUARANTINE = "QUARANTINE"
