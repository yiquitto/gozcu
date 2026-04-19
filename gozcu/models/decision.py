"""
Decision Model.

Represents a pending decision within the 30-second countdown state machine.
Unlike other models, Decision is NOT frozen because its state changes
over its lifecycle (PENDING → APPROVED/REJECTED/AUTONOMOUS/EXPIRED).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from gozcu.models.enums import DecisionState


class Decision(BaseModel):
    """A mutable decision record tracked by the state machine."""

    # NOT frozen — state changes during countdown lifecycle
    model_config = ConfigDict(frozen=False)

    # Identity
    decision_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_id: str = Field(..., description="UUID of the triggering TelemetryEvent")

    # State
    state: DecisionState = Field(default=DecisionState.PENDING)

    # Timestamps
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    resolved_at: Optional[str] = Field(
        default=None,
        description="Timestamp when decision was finalized",
    )

    # Resolution
    resolved_by: str = Field(
        default="",
        description="'ANALYST:username' or 'GOZCU:AUTONOMOUS'",
    )
    action_taken: Optional[str] = Field(
        default=None,
        description="Action executed (e.g. BLOCK_IP, NULL_ROUTE)",
    )

    # Timer
    timeout_seconds: int = Field(default=30)

    def approve(self, analyst: str) -> None:
        """Analyst approves the recommended action."""
        self.state = DecisionState.APPROVED
        self.resolved_at = datetime.now(timezone.utc).isoformat()
        self.resolved_by = f"ANALYST:{analyst}"

    def reject(self, analyst: str) -> None:
        """Analyst rejects the recommended action."""
        self.state = DecisionState.REJECTED
        self.resolved_at = datetime.now(timezone.utc).isoformat()
        self.resolved_by = f"ANALYST:{analyst}"

    def mark_autonomous(self, action: str) -> None:
        """System takes autonomous action after timeout."""
        self.state = DecisionState.AUTONOMOUS
        self.resolved_at = datetime.now(timezone.utc).isoformat()
        self.resolved_by = "GOZCU:AUTONOMOUS"
        self.action_taken = action

    def mark_expired(self) -> None:
        """Timeout reached but confidence too low for autonomous action."""
        self.state = DecisionState.EXPIRED
        self.resolved_at = datetime.now(timezone.utc).isoformat()
        self.resolved_by = "GOZCU:EXPIRED"

    @property
    def is_resolved(self) -> bool:
        """Check if this decision has reached a terminal state."""
        return self.state in (
            DecisionState.APPROVED,
            DecisionState.REJECTED,
            DecisionState.AUTONOMOUS,
            DecisionState.EXPIRED,
        )
