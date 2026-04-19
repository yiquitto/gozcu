"""
Log Ingestor.

Central entry point for the ingestion pipeline. Receives raw log data,
selects the appropriate parser based on source type, sanitizes input,
normalizes the output, and produces a TelemetryEvent with UUID and SHA-256 hash.
"""

from __future__ import annotations

import logging
from typing import Optional

from gozcu.models.enums import SourceType
from gozcu.models.telemetry_event import TelemetryEvent
from gozcu.ingestion.sanitizer import InputSanitizer
from gozcu.ingestion.parsers.syslog_parser import SyslogParser
from gozcu.ingestion.parsers.windows_parser import WindowsEventParser
from gozcu.ingestion.parsers.json_parser import JsonWebLogParser

logger = logging.getLogger(__name__)


class LogIngestor:
    """
    Orchestrates the log ingestion pipeline.

    Flow: Raw Data → Sanitize → Parse → Normalize → UUID + SHA-256 → TelemetryEvent
    """

    def __init__(self) -> None:
        self._sanitizer = InputSanitizer()
        self._parsers = {
            SourceType.SYSLOG: SyslogParser(),
            SourceType.WINDOWS_EVENT: WindowsEventParser(),
            SourceType.WEB_LOG: JsonWebLogParser(),
        }
        self._stats = {"total": 0, "success": 0, "malformed": 0, "injection_detected": 0}

    async def ingest(
        self,
        raw_data: str,
        source_type: SourceType,
        source_ip: str = "0.0.0.0",
    ) -> Optional[TelemetryEvent]:
        """
        Ingest a single raw log entry and produce a TelemetryEvent.

        Returns None only if the input is completely empty.
        Malformed logs are still ingested but flagged in normalized_data.
        """
        self._stats["total"] += 1

        if not raw_data or not raw_data.strip():
            logger.debug("Empty log entry received, skipping")
            return None

        # Step 1: Sanitize
        sanitized = self._sanitizer.sanitize(raw_data)

        # Check for injection attempts
        if self._sanitizer.detect_injection(raw_data):
            self._stats["injection_detected"] += 1
            logger.warning(
                "Log injection pattern detected",
                extra={"source_ip": source_ip, "source_type": source_type.value},
            )

        # Step 2: Parse
        parser = self._parsers.get(source_type)
        if parser is None:
            logger.error(f"No parser available for source type: {source_type.value}")
            normalized = {"format": "UNKNOWN", "message": sanitized, "malformed": True}
        else:
            normalized = parser.parse(sanitized)

        # Step 3: Handle parse failure — tag as MALFORMED, don't drop
        if normalized is None:
            self._stats["malformed"] += 1
            logger.warning(
                "Malformed log entry — tagging as MALFORMED",
                extra={"source_ip": source_ip, "source_type": source_type.value},
            )
            normalized = {
                "format": "MALFORMED",
                "message": sanitized,
                "malformed": True,
                "original_source_type": source_type.value,
            }
        else:
            self._stats["success"] += 1

        # Step 4: Extract source_ip from parsed data if not provided
        if source_ip == "0.0.0.0":
            source_ip = self._extract_source_ip(normalized, source_ip)

        # Step 5: Build TelemetryEvent (UUID + SHA-256 computed by factory)
        event = TelemetryEvent.create(
            raw_data=raw_data,  # Hash is computed on ORIGINAL raw data, not sanitized
            source_type=source_type,
            source_ip=source_ip,
            normalized_data=normalized,
        )

        logger.info(
            "Event ingested",
            extra={
                "event_id": event.event_id,
                "source_type": source_type.value,
                "source_ip": source_ip,
            },
        )

        return event

    @staticmethod
    def _extract_source_ip(normalized: dict, fallback: str) -> str:
        """Try to extract source IP from parsed log data."""
        for key in ("source_ip", "remote_addr", "client_ip", "ip"):
            val = normalized.get(key)
            if val and isinstance(val, str) and val.strip():
                return val.strip()
        return fallback

    def get_stats(self) -> dict:
        """Return ingestion statistics."""
        return dict(self._stats)
