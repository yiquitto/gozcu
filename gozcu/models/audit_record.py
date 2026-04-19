"""
AuditRecord Model.

Immutable record of every decision made by the system (human or autonomous).
Each record includes a SHA-256 hash of its own serialized content for
tamper detection in the audit trail.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field


class AuditRecord(BaseModel):
    """A tamper-evident audit log entry."""

    model_config = ConfigDict(frozen=True)

    # Identity
    audit_id: str = Field(default_factory=lambda: str(uuid.uuid4()))

    # Timestamps
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )

    # References
    event_id: str = Field(..., description="UUID of the TelemetryEvent")
    decision_id: str = Field(..., description="UUID of the Decision")

    # Action details
    action: str = Field(..., description="Action taken (e.g. BLOCK_IP, MONITOR)")
    actor: str = Field(
        ...,
        description="Who took the action: 'ANALYST:name' or 'GOZCU:AUTONOMOUS'",
    )

    # AI context at decision time
    threat_score: int = Field(default=0)
    confidence: float = Field(default=0.0)
    ai_reasoning: str = Field(default="")

    # Outcome
    outcome: str = Field(
        default="",
        description="Result of the action (e.g. 'IP blocked', 'Simulated')",
    )

    # Integrity
    record_hash: str = Field(
        default="",
        description="SHA-256 hash of this record for tamper detection",
    )

    def compute_record_hash(self) -> str:
        """Compute SHA-256 hash of this record's content (excluding record_hash itself)."""
        # Serialize all fields except record_hash for hash computation
        content = (
            f"{self.audit_id}|{self.timestamp}|{self.event_id}|"
            f"{self.decision_id}|{self.action}|{self.actor}|"
            f"{self.threat_score}|{self.confidence}|{self.ai_reasoning}|"
            f"{self.outcome}"
        )
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @classmethod
    def create(
        cls,
        event_id: str,
        decision_id: str,
        action: str,
        actor: str,
        threat_score: int = 0,
        confidence: float = 0.0,
        ai_reasoning: str = "",
        outcome: str = "",
    ) -> AuditRecord:
        """Factory that auto-computes the tamper-detection hash."""
        record = cls(
            event_id=event_id,
            decision_id=decision_id,
            action=action,
            actor=actor,
            threat_score=threat_score,
            confidence=confidence,
            ai_reasoning=ai_reasoning,
            outcome=outcome,
        )
        # Re-create with computed hash (frozen model requires reconstruction)
        return cls(
            audit_id=record.audit_id,
            timestamp=record.timestamp,
            event_id=record.event_id,
            decision_id=record.decision_id,
            action=record.action,
            actor=record.actor,
            threat_score=record.threat_score,
            confidence=record.confidence,
            ai_reasoning=record.ai_reasoning,
            outcome=record.outcome,
            record_hash=record.compute_record_hash(),
        )
