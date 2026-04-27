"""
TelemetryEvent Model.

Represents a single normalized log event ingested from any source.
Every event receives a unique UUID and a SHA-256 integrity hash
computed over the raw data at ingestion time.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from pydantic import BaseModel, ConfigDict, Field, field_validator


from gozcu.models.enums import SourceType


class TelemetryEvent(BaseModel):
    """A normalized, integrity-verified telemetry event."""
    # hocaya not: sisteme giren her log satirina degistirilemez (frozen) bir kimlik karti cikartiyorum. logun orijinal halini asla bozmayip uzerinden hash aliyorum ki adli bilisimde (forensics) kanit niteligi tasisin.

    model_config = ConfigDict(frozen=True)

    # Identity
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))

    # Timestamps
    timestamp: str = Field(
        ...,
        description="Original event timestamp in ISO-8601 UTC",
    )
    ingestion_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )

    # Source
    source_type: SourceType
    source_ip: str = Field(default="0.0.0.0")

    # Data
    raw_data: str = Field(..., description="Original unmodified log line")
    normalized_data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Parser output — structured key-value pairs",
    )

    # Integrity
    integrity_hash: str = Field(
        default="",
        description="SHA-256 hex digest of raw_data",
    )

    @field_validator("source_ip")
    @classmethod
    def validate_ip_not_empty(cls, v: str) -> str:
        """Ensure source_ip is never an empty string."""
        if not v or not v.strip():
            return "0.0.0.0"
        return v.strip()

    @staticmethod
    def compute_hash(raw_data: str) -> str:
        """Compute SHA-256 hex digest for the given raw data string."""
        return hashlib.sha256(raw_data.encode("utf-8")).hexdigest()

    @classmethod
    def create(
        cls,
        raw_data: str,
        source_type: SourceType,
        source_ip: str = "0.0.0.0",
        timestamp: str | None = None,
        normalized_data: Dict[str, Any] | None = None,
    ) -> TelemetryEvent:
        """Factory method that auto-computes the integrity hash."""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).isoformat()
        return cls(
            raw_data=raw_data,
            source_type=source_type,
            source_ip=source_ip,
            timestamp=timestamp,
            normalized_data=normalized_data or {},
            integrity_hash=cls.compute_hash(raw_data),
        )
